# Spamtrap

[![Test](https://github.com/cedric/spamtrap/actions/workflows/test.yml/badge.svg)](https://github.com/cedric/spamtrap/actions/workflows/test.yml)

Spamtrap is a Rails gem that protects forms from spambots through three complementary
mechanisms:

- **Honeypot fields** — hidden textarea fields that real users never touch. Bots that fill
  them in are silently discarded with a `200 OK` response.
- **Nonce** — an HMAC-SHA256 token binding each submission to a render timestamp, the client
  IP, and the honeypot name. It is a freshness check, not replay protection, unless you opt
  into `:single_use` mode (see below).
- **Field name mutation** — form field names are AES-128-GCM encrypted on render, so bots
  cannot target fields by recognizable names like `email` or `body`. The controller remaps
  them back transparently. `mutate: true` (and `:strict`) additionally rejects any submission
  containing a plaintext field name; use `mutate: :lenient` for remap-only.

Each feature is opt-in and can be used independently or combined. None of them is a complete
defense on its own — read the guarantees below before relying on one.

## What each feature does and does not guarantee

| Feature | Guarantees | Does **not** guarantee |
|---|---|---|
| Honeypot | Traps bots that auto-fill hidden fields | Traps a bot that knows to skip hidden fields |
| Nonce (`nonce: true`) | The form was rendered by this app, for this IP and honeypot, within `nonce_timeout` | Replay protection — the same valid token is accepted repeatedly until it expires |
| Nonce (`nonce: :single_use`) | The above, plus: a given nonce is accepted once | Replay detection without a shared cache store; a `NullStore` accepts every write (see [Testing](#testing)) |
| Mutation (`mutate: true` / `:strict`) | Hides field names from scrapers of a given render, and rejects any submitted key that isn't a valid mutation token | Working without updating `allowed_params` for any custom, non-form params your app posts |
| Mutation (`mutate: :lenient`) | Hides field names from scrapers of a given render | Stopping a bot that already knows the real field names — plaintext names still pass through |

## Installation

Requires Ruby 3.1 or newer and Rails 7.2 or newer. CI runs Ruby 3.4 and 4.0 against Rails 7.2 through 8.1.

Add the following to your Gemfile:

```ruby
gem 'spamtrap'
```

Spamtrap installs itself into `ActionController::Base` and `ActionView::Helpers::FormBuilder`
via `Spamtrap::Railtie`, from `on_load` hooks that fire after your app's own initializers run —
no explicit setup needed in a Rails app.

### Outside Rails

If you're using `actionpack`/`actionview` without a full Rails application (no `Rails::Railtie`
loaded), require the gem and install it yourself once Action Controller and Action View are
loaded:

```ruby
require 'spamtrap'
Spamtrap.install!
```

## Configuration

Global defaults can be set in an initializer. Per-controller or per-action options always
take precedence, including an explicit `false` that overrides a global `true`. All of these
are read at request time, so changes take effect immediately without restarting the server.

```ruby
# config/initializers/spamtrap.rb
Spamtrap.enabled          = true          # false skips every check (honeypot, nonce, mutation); for test environments
Spamtrap.nonce            = false        # false, true, or :single_use
Spamtrap.nonce_timeout    = 1800          # seconds; also caps mutation token age unless mutation_timeout is set
Spamtrap.mutation_timeout = nil           # defaults to nonce_timeout
Spamtrap.nonce_skew       = 60            # seconds a submitted timestamp may sit in the future
Spamtrap.nonce_store      = Rails.cache   # where :single_use records seen nonce ids
Spamtrap.nonce_bind_ip    = true          # true (full IP, default), :prefix (/24 IPv4 or /48 IPv6), or false (not bound)
Spamtrap.mutate           = false         # false, true/:strict (traps plaintext keys), or :lenient (remap only)
Spamtrap.allowed_params   = []            # extra top-level param names a strict action accepts unencrypted
Spamtrap.trap_response    = :head         # see "Trap response, Turbo and remote forms" below
Spamtrap.on_trap          = ->(reason:, request:) { ... }  # optional trap callback
```

The same options can be set per controller action:

```ruby
spamtrap :sarah_palin_walks_with_dinosaurs,
         only: %i[create update],
         nonce: true,
         nonce_timeout: 60,
         mutate: :strict,
         trap_response: :unprocessable,
         on_trap: ->(reason:, request:) { ... }
```

### Trap callback (`on_trap`)

An optional callback is invoked whenever the spamtrap fires — honeypot, nonce, or mutation.
Use it for logging, metrics, rate-limiting, or any other custom behaviour.

Set a global callback in the initializer:

```ruby
# config/initializers/spamtrap.rb
Spamtrap.on_trap = lambda do |reason:, request:, controller:, honeypot:, params:|
  # reason is one of :honeypot, :nonce_missing, :nonce_expired, :nonce_invalid,
  # :nonce_replayed, :plaintext_field, :mutation_expired
  Rails.logger.warn "[Spamtrap] #{reason} trap fired from #{request.remote_ip} on #{request.path}"
  StatsD.increment('spamtrap.triggered', tags: ["reason:#{reason}"])
end
```

Or override per declaration (takes precedence over the global callback):

```ruby
spamtrap :comment, only: :create, on_trap: ->(reason:, request:) {
  Honeybadger.notify("Spamtrap fired", context: { reason: reason, ip: request.remote_ip })
}
```

Only the keywords your callback actually declares are passed, so an existing
`->(reason:, request:) { ... }` callback keeps working unchanged. Available keywords:

- `reason:` — see the list above.
- `request:` — the `ActionDispatch::Request` object (IP, path, headers, etc.).
- `controller:` — the controller instance handling the request.
- `honeypot:` — the honeypot field name declared for this action.
- `params:` — the request params, already remapped to real field names when mutation is on.

Exceptions raised inside the callback are rescued and logged; a broken callback never
prevents the trap response from being sent. If the callback renders or redirects itself,
that response is used instead of `trap_response`.

## Honeypot

A hidden textarea is added to the form with a deliberately enticing name. Real users never see
or interact with it — `f.spamtrap` renders it with `tabindex="-1"`, `autocomplete="off"`,
`aria-hidden="true"`, and an inline `style="display:none"` by default, so no app CSS is
required to hide it. Spambots, which auto-fill all visible and hidden fields, will populate it.
When the form is submitted with a non-empty honeypot field, spamtrap discards the submission
with `reason: :honeypot`.

Declare the controller actions you want protected:

```ruby
class CommentsController < ApplicationController
  spamtrap :sarah_palin_walks_with_dinosaurs, only: %i[create update]
end
```

Add the honeypot field to your form using the `f.spamtrap` form builder helper:

```erb
<%= form_for @comment do |f| %>
  <%= f.spamtrap :sarah_palin_walks_with_dinosaurs, class: 'reindeer_jerky' %>
  <fieldset>
    <%= f.label :body %>
    <%= f.text_area :body %>
  </fieldset>
  <%= f.submit %>
<% end %>
```

Any of the default attributes can be overridden by passing it explicitly — `style: nil` removes
the inline hide for apps that prefer their own CSS, and `tabindex: nil` restores the honeypot to
the tab order (e.g. to also catch keyboard-driven bots):

```erb
<%= f.spamtrap :sarah_palin_walks_with_dinosaurs, style: nil, class: 'reindeer_jerky' %>
```

```css
.reindeer_jerky { display: none; }
```

If you enable mutation via the `spamtrap:` option on `form_for`/`form_with` (the recommended
way — see [Field Name Mutation](#field-name-mutation)), field order doesn't matter. If instead
you pass `mutate:` directly to `f.spamtrap`, call it **before** any other field helper in the
form; fields rendered before it are not mutated.

## Nonce

The nonce is an HMAC-SHA256 digest over `v1:timestamp:client_ip:honeypot_name:nonce_id`,
keyed with an HKDF-derived key (from `Rails.application.secret_key_base`). It proves the
form was rendered by this app, for this client IP, for this honeypot, within the timeout
window, and not more than `nonce_skew` seconds in the future.

**This is a freshness check, not replay protection.** By itself (`nonce: true`), the same
valid token is accepted any number of times until it expires — a captured, valid submission
can be replayed. If you need replay protection, use `nonce: :single_use` instead.

Enable globally via the initializer, or per-controller:

```ruby
spamtrap :sarah_palin_walks_with_dinosaurs, nonce: true, only: %i[create update]
```

Add the nonce fields to your form:

```erb
<%= form_for @comment do |f| %>
  <%= f.spamtrap :sarah_palin_walks_with_dinosaurs, nonce: true, class: 'reindeer_jerky' %>
<% end %>
```

Rendering the nonce fields needs an actual request to bind them to (for the client IP);
calling `f.spamtrap nonce: true` from a mailer view, or from `ApplicationController.render`
outside a request, raises `Spamtrap::NoRequestError`.

Override the timeout for a specific action (seconds, or an `ActiveSupport::Duration`):

```ruby
spamtrap :field, nonce: true, nonce_timeout: 15.minutes, only: %i[create]
```

### Single-use nonces

```ruby
spamtrap :field, nonce: :single_use, only: %i[create]
```

On first successful use, the `nonce_id` is recorded in `Spamtrap.nonce_store` (default
`Rails.cache`); a second submission with the same `nonce_id` is rejected with
`reason: :nonce_replayed`. This requires a real, shared cache store in production — Redis,
Memcached, or Solid Cache. With `ActiveSupport::Cache::NullStore` (Rails' test-environment
default), Spamtrap logs one warning per process and cannot detect replays at all, because
every write to a `NullStore` succeeds.

The trade-off: a legitimate user who submits the same page twice — double-click, back
button, browser retry — is rejected the second time, same as a replayed bot submission.

### Nonce failure reasons

Passed to `on_trap` as `reason:`:

- `:nonce_missing` — timestamp, nonce, or nonce id absent from the submission.
- `:nonce_expired` — timestamp older than the timeout.
- `:nonce_invalid` — bad HMAC, wrong form, wrong IP, timestamp too far in the future, or a
  malformed nonce id.
- `:nonce_replayed` — `:single_use` only; the nonce id was already seen.

### IP binding

`Spamtrap.nonce_bind_ip` controls how tightly the nonce is bound to the client IP:

- `true` (default) — binds to the full client IP. Users whose IP address changes between page
  load and form submission — mobile network handoffs, CGNAT — are rejected with
  `:nonce_invalid`.
- `:prefix` — binds to the request's /24 network for IPv4, or /48 for IPv6, instead of the
  exact address. An IPv4-mapped IPv6 address (e.g. `::ffff:203.0.113.5`) is masked as IPv4
  first, not folded into a single /48. This tolerates most mobile carrier and CGNAT address
  churn while still requiring the submission to come from roughly where the form was rendered.
- `false` — the nonce isn't bound to the IP at all.

Sites with a significant mobile user base should prefer `:prefix` over the default `true`,
since a full carrier IP change between page load and submission is common on mobile networks
and would otherwise reject legitimate users.

## Field Name Mutation

Every field is encrypted with AES-128-GCM, using a random IV per field and the render
timestamp as associated data, so field names are unrecognizable in HTML source, change on
every render, and expire after `mutation_timeout` (defaults to `nonce_timeout`). The
controller decrypts and remaps them transparently before the action runs — no changes to
`params.require(...).permit(...)` or any other controller code required.

**`mutate: true` is strict by default.** It hides field names from scrapers of that render
*and* rejects any submitted key that isn't a valid mutation token, with
`reason: :plaintext_field` (see [Strict mutation](#strict-mutation) below). Use
`mutate: :lenient` if you only want field names hidden, without rejecting a bot that already
knows the real field names (from source, docs, or a previous unmutated render) — under
`:lenient`, submitted plaintext names are simply left alone and pass through like any other
params.

Enable globally via the initializer, or per-controller:

```ruby
spamtrap :sarah_palin_walks_with_dinosaurs, mutate: true, only: %i[create update]
```

The recommended way to enable it in the view is the `spamtrap:` option on `form_with` (or
`form_for`), which mints the shared render timestamp when the builder is constructed — so it
no longer matters where in the form you call `f.spamtrap`, or whether you call it before or
after the fields it protects:

```erb
<%= form_with model: @comment, spamtrap: { mutate: true } do |f| %>
  <%= f.label :body %>
  <%= f.text_area :body %>
  <%= f.label :email %>
  <%= f.email_field :email %>
  <%= f.spamtrap :sarah_palin_walks_with_dinosaurs %>
  <%= f.submit %>
<% end %>
```

`f.spamtrap` needs no `mutate:` argument here — it inherits `mutate:` (and `nonce:`) from the
options the builder was constructed with. Combine both in the same hash:

```ruby
form_with model: @comment, spamtrap: { mutate: true, nonce: true }
```

If you don't pass `spamtrap:` to `form_with`/`form_for`, pass `mutate: true` directly to
`f.spamtrap` instead — but then call it **before** any other field helper, since the shared
render timestamp isn't minted until `f.spamtrap` runs, and fields rendered before it are not
mutated:

```erb
<%= form_for @comment do |f| %>
  <%= f.spamtrap :sarah_palin_walks_with_dinosaurs, mutate: true %>
  <%= f.label :body %>
  <%= f.text_area :body %>
  <%= f.label :email %>
  <%= f.email_field :email %>
  <%= f.submit %>
<% end %>
```

The rendered HTML will contain opaque encrypted field names instead of `body`, `email`,
etc. The encryption key is derived from `secret_key_base`, so only the originating server
can decrypt submissions.

Mutation can be combined with the nonce for freshness plus name hiding:

```ruby
spamtrap :field, mutate: true, nonce: true, only: %i[create update]
```

```erb
<%= f.spamtrap :field, mutate: true, nonce: true %>
```

Mutation propagates automatically to `fields_for` nested builders and into arrays of nested
builders, so nested attributes forms are mutated at every level without extra configuration.

Model-backed forms remain fully supported: helpers still pre-populate from model values while
rendering encrypted field names in the HTML.

### Helper coverage

Every `FormBuilder` field helper is mutated: `text_field`, `email_field`, `password_field`,
`number_field`, `url_field`, `telephone_field`/`phone_field`, `text_area`, `check_box`,
`radio_button`, `hidden_field`, `file_field`, `date_field`, `time_field`, `datetime_field`,
`datetime_local_field`, `month_field`, `week_field`, `search_field`, `color_field`,
`range_field`, `select`, `collection_select`, `grouped_collection_select`, `time_zone_select`,
`weekday_select`, `collection_check_boxes`, `collection_radio_buttons`, `date_select`,
`time_select`, `datetime_select`, `label`, and `rich_text_area` when Action Text is loaded.
Rails' multi-parameter field names for the date/time selects (e.g. `field(1i)`, `field(2i)`)
are remapped correctly — the base field name is decrypted and the `(Ni)` suffix is preserved.

### Stable ids and validation errors

Element `id`s and label `for` attributes are derived from the real field name (e.g.
`comment_body`), while `name` stays encrypted — so your CSS, Stimulus targets, and browser
autofill keep working exactly as they would on an unmutated form. Set
`Spamtrap.stable_ids = false` to opt out and fall back to an id derived from the opaque
encrypted name instead. `collection_check_boxes`, `collection_radio_buttons`, and the
`date_select`/`time_select`/`datetime_select` helpers always keep their own opaque ids — Rails
computes those per collection item or multi-parameter field internally.

`field_with_errors` wrapping (Rails' default `ActionView::Base.field_error_proc`) works on
mutated fields: Spamtrap resolves the model's errors using the real field name before handing
off to the wrapper.

### Strict mutation

`mutate: true` and `mutate: :strict` are equivalent, and this is the default `mutate:`
behaviour: any submitted top-level or nested key that is not a valid mutation token is treated
as a trap, with `reason: :plaintext_field` — except for a fixed allowlist:
`authenticity_token`, `commit`, `button`, `_method`, `utf8`, the `spamtrap_*` hidden fields,
the honeypot field name, Rails' own routing params (`controller`, `action`, `id`, `format`),
and anything you add to `Spamtrap.allowed_params`. Object and `fields_for` container names
(e.g. `comment` in `comment[body]`) are structure, not fields, and are never flagged
themselves — but a plaintext key found *inside* one still traps.

Three captcha widgets' response params are also allowlisted by default, since the widget
injects them as plaintext and the app has no way to encrypt them: `g-recaptcha-response`
(Google reCAPTCHA v2/v3), `h-captcha-response` (hCaptcha), and `cf-turnstile-response`
(Cloudflare Turnstile). Any other widget's plaintext param needs adding to
`Spamtrap.allowed_params` yourself.

A missing render timestamp is reported as `reason: :mutation_expired` rather than
`:plaintext_field`, since nothing could be decrypted to tell a real violation from a missing
one. An *expired* render timestamp (older than `mutation_timeout`, or too far in the future)
is also `reason: :mutation_expired` — in both `:strict` and `:lenient` mode — but unlike a
missing timestamp, every field is still decrypted and remapped to its real name before the
trap fires, with no additional staleness bound on that remap. This lets `on_trap` and a
`trap_response` callable re-render the form with what the user actually typed, using
`params`/`controller.params` as normal, instead of showing them an empty form again. The
action itself never runs either way.

If your app posts any custom top-level params that aren't part of the form (e.g. a query
string param merged into a redirect, or a param your JS adds), add them to
`Spamtrap.allowed_params` or the action will trap on them.

Use `mutate: :lenient` to opt out of strict checking and go back to remap-only behaviour —
field names are still hidden, but a submitted plaintext field name is never trapped:

```ruby
spamtrap :field, mutate: :lenient, only: %i[create update]
```

## Trap response, Turbo and remote forms

By default, a trapped submission gets `Spamtrap.trap_response = :head` — an empty `200 OK`,
indistinguishable from success to a bot and to any polling script. This is ideal for
honeypot traps, which no legitimate user should ever hit, but it is a poor experience when a
*human* is trapped by mistake — for example a legitimate double-submission caught by
`nonce: :single_use`, or a cached, stale nonce.

`trap_response` accepts:

- `:head` — 200, empty body (default).
- `:no_content` — 204.
- `:unprocessable` — 422.
- `:redirect_back` — 303 to the referer, or `/` if there is none.
- A callable — `->(controller, reason) { controller.render ... }`.
- A `Hash` keyed by reason, with a `:default` key for anything not listed, e.g.:

  ```ruby
  Spamtrap.trap_response = {
    honeypot: :head,          # stay silent for bots
    nonce_expired: :unprocessable,
    nonce_replayed: :unprocessable,
    default: :head
  }
  ```

If `on_trap` renders or redirects itself, that response wins over `trap_response`.

**Turbo apps in particular should not use `:head` for reasons a human can plausibly hit.**
Turbo Drive expects a form submission to answer with a redirect or a 4xx/5xx status. On a
`200` it logs "Form responses must redirect to another location" and renders nothing, so a
trapped human sees no feedback at all. Use `:unprocessable` (Turbo renders the response) or
`:redirect_back`, and keep `:honeypot` on `:head` since a human should never trigger it.

**rails-ujs/jquery-ujs `remote: true` forms have the same problem, in a different shape.**
An empty `200` fires the form's `ajax:success` handler with an empty body — a modal that
treats "success fired" as "the message sent" closes itself, and the trapped human walks away
thinking it went through. An empty `422` fires `ajax:error`, but with nothing in the response
to render, so there's still no visible feedback.

The fix is the same for both: a callable that re-renders the form with a 422 and a visible
error, instead of an empty body either way.

```ruby
Spamtrap.trap_response = {
  honeypot: :head,
  plaintext_field: :head,
  default: lambda do |controller, reason|
    controller.flash.now[:alert] = 'Your form expired or was sent twice. Please check it and send it again.'
    controller.render controller.action_name == 'create' ? :new : :edit,
                       layout: !controller.request.xhr?,
                       status: :unprocessable_entity
  end
}
```

`layout: !controller.request.xhr?` skips the layout for the `remote: true`/Turbo Stream
request (which only needs the form partial back) while still rendering it for a normal
full-page submission. The reasons a human can plausibly hit in 0.4.0 — the ones worth a
`default` branch like this rather than a silent `:head` — are `:nonce_expired`,
`:mutation_expired`, `:nonce_invalid` (most often an IP change between page load and submit),
and `:nonce_replayed` (a double submit under `nonce: :single_use`).

## Caching

Fragment, page, or CDN caching of a rendered form freezes the render timestamp, client IP,
and nonce into the cached HTML. Once that snapshot is older than the timeout, *every*
visitor served the cached form is rejected, regardless of whether they're a bot — because
the nonce and mutation tokens they submit are the same ones baked into the cache, no matter
who requests the page or when.

Either:

- Exclude the `f.spamtrap` output from whatever you cache, and render it fresh outside the
  cached fragment, or
- Turn `nonce` and `mutate` off for forms you cache.

## Testing

Tests that post to a protected action need valid `spamtrap_timestamp` and nonce fields in the
params, built the same way the view helper builds them, or the request will be trapped.
`Spamtrap::TestHelper` builds them for you. It's not required by `spamtrap` itself, so pull it
in explicitly and include it in your test cases:

```ruby
require 'spamtrap/test_helper'

class ActionController::TestCase
  include Spamtrap::TestHelper
end
```

It provides:

- `spamtrap_params(honeypot:, ip: '0.0.0.0', nonce: false, mutate: false, at: Time.now.to_i, fields: nil)` —
  the params hash a protected action needs: the empty honeypot field, plus whatever
  `spamtrap_timestamp`/nonce fields the declared options require. `fields:` is merged in —
  through `spamtrap_mutate` first when `mutate:` is truthy, unchanged otherwise — so one call
  builds the whole POST.
- `spamtrap_token(name, timestamp)` — encrypts a real field name into the same kind of
  mutation token the view helper renders, for posting to a `mutate:`-protected action.
- `spamtrap_decrypt(token, timestamp)` — the reverse, for asserting on a token your app
  captured.
- `spamtrap_mutate(hash, at:)` — encrypts every field name in a whole params hash the way the
  form builder renders them, so it round-trips through a `mutate:`-protected action without
  hand-building a token per field. Object/`fields_for` container names (a key whose value is a
  Hash, or an Array of Hashes) are left plaintext and recursed into; every other key — including
  one whose value is an array of scalars — is encrypted, with a trailing multi-parameter suffix
  like `published_on(1i)` preserved after the token.
- `spamtrap_nonce_params(honeypot:, ip:, at: Time.now.to_i, nonce_id: SecureRandom.hex(16))` —
  just the nonce fields, if you need them without the honeypot key.

```ruby
class CommentsControllerTest < ActionController::TestCase
  def test_create_with_mutation_and_nonce
    ts = Time.now.to_i
    params = spamtrap_params(honeypot: 'field', ip: '127.0.0.1', nonce: true, mutate: true, at: ts)
             .merge(comment: { spamtrap_token('body', ts) => 'hi' })

    @request.remote_addr = '127.0.0.1'
    post :create, params: params

    assert_response :success
  end

  def test_create_with_a_whole_mutated_form
    ts = Time.now.to_i
    params = spamtrap_params(honeypot: 'field', mutate: true, at: ts,
                              fields: { comment: { body: 'hi', address: { city: 'Springfield' } } })

    post :create, params: params

    assert_response :success
  end
end
```

The nonce is bound to the client IP (see [IP binding](#ip-binding)), so the `ip:` you pass to
`spamtrap_params`/`spamtrap_nonce_params` must match the test request's `remote_addr` —
`ActionController::TestCase` defaults `remote_addr` to `'0.0.0.0'`.

`Rails.cache` is usually `ActiveSupport::Cache::NullStore` in the test environment, which
means `nonce: :single_use` cannot detect replays there (see [Single-use nonces](#single-use-nonces))
— assert on the first submission's behaviour, not on rejecting a second one, unless you
swap in a real cache store for that test.

Alternatively, set `Spamtrap.enabled = false` for the whole test environment to skip every
check, or declare `nonce: false` (and `mutate: false`) on the action under test — or use a
`spamtrap :field, only: :create, nonce: false` override in a test-only subclass — if the nonce
or mutation behaviour itself isn't what's under test.

## License

(The MIT License)

Copyright (c) 2010-2026 Cedric Howe

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
