# Spamtrap

[![Test](https://github.com/cedric/spamtrap/actions/workflows/test.yml/badge.svg)](https://github.com/cedric/spamtrap/actions/workflows/test.yml)

Spamtrap is a Rails gem that protects forms from spambots through a set of complementary,
individually opt-in mechanisms:

- **Honeypot fields** — hidden textarea fields that real users never touch. Bots that fill
  them in are silently discarded with a `200 OK` response.
- **Nonce** — an HMAC-SHA256 token binding each submission to a render timestamp, the client
  IP, and the honeypot name. It is a freshness check, not replay protection, unless you opt
  into `:single_use` mode (see below).
- **Field name mutation** — form field names are AES-128-GCM encrypted on render, so bots
  cannot target fields by recognizable names like `email` or `body`. The controller remaps
  them back transparently. `mutate: true` (and `:strict`) additionally rejects any submission
  containing a plaintext field name; use `mutate: :lenient` for remap-only.

- **Minimum fill time** — submissions arriving less than a second after the form was rendered
  are rejected; scripted posters usually submit within milliseconds.
- **JavaScript proof of presence** — an optional hidden field only an executing script fills
  in, for forms where excluding no-JS users is acceptable.
- **Content hook** — an app-supplied check on the submitted params, given the same trap
  response, callback and instrumentation as the built-in checks.
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
| Minimum fill time (`min_fill_time`) | Rejects a submission received less than `min_fill_time` seconds after a verified render, when `nonce` or `mutate` is on | Anything on a honeypot-only form — there's no verified timestamp to check it against |
| JS proof (`js_proof: true`) | Traps a client that never executes JavaScript | Traps a headless browser, or a bot that parses the page's script and computes the value itself |
| Content hook (`suspicious_if:`) | Runs your own heuristic with the same trap response, callback, and instrumentation as the built-in checks | Any spam detection itself — that logic is entirely yours |

## Installation

Requires Ruby 3.1 or newer and Rails 7.2 or newer. CI runs Ruby 3.4 and 4.0 against Rails 7.2 through 8.1.

Add the following to your Gemfile:

```ruby
gem 'spamtrap'
```

Spamtrap installs itself into `ActionController::Base` and `ActionView::Helpers::FormBuilder`
via `Spamtrap::Railtie`, from `on_load` hooks that fire after your app's own initializers run —
no explicit setup needed in a Rails app. `ActionController::API` subclasses get the `spamtrap`
macro the same way, so a JSON-only endpoint can use it too.

Then run the install generator to write an initializer documenting every configuration option
at its default, commented out:

```
rails g spamtrap:install
```

This creates `config/initializers/spamtrap.rb`. Uncomment and change only the options you want
to override — see [Configuration](#configuration) below for what each one does. Writing the
file yourself instead of running the generator works just as well; the generator just saves you
copying the option list out of this README.

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
Spamtrap.honeypot_styles  = [:textarea]   # decoys f.spamtrap renders: any of :textarea, :text, :checkbox
Spamtrap.js_proof         = false         # require a hidden field only an executing script fills in
Spamtrap.nonce            = false        # false, true, or :single_use
Spamtrap.nonce_timeout    = 1800          # seconds; also caps mutation token age unless mutation_timeout is set
Spamtrap.mutation_timeout = nil           # defaults to nonce_timeout
Spamtrap.nonce_skew       = 60            # seconds a submitted timestamp may sit in the future
Spamtrap.nonce_store      = Rails.cache   # where :single_use records seen nonce ids
Spamtrap.nonce_bind_ip    = true          # true (full IP, default), :prefix (/24 IPv4 or /48 IPv6), or false (not bound)
Spamtrap.min_fill_time    = 1             # seconds; false or 0 disables; needs nonce or mutate for a trustworthy timestamp
Spamtrap.mutate           = false         # false, true/:strict (traps plaintext keys), or :lenient (remap only)
Spamtrap.allowed_params   = []            # extra top-level param names a strict action accepts unencrypted
Spamtrap.filter_parameters = true         # apply config.filter_parameters to mutated field names in the log
Spamtrap.trap_response    = :head         # see "Trap response, Turbo and remote forms" below
Spamtrap.on_trap          = ->(reason:, request:) { ... }  # optional trap callback
Spamtrap.suspicious_if    = nil           # optional content hook; see "Content hook" below
Spamtrap.secret_key_base          = nil   # defaults to Rails.application.secret_key_base
Spamtrap.previous_secret_key_base = nil   # set during a rotation window; see "Rotating secret_key_base" below
Spamtrap.token_context            = nil   # binds tokens to a per-request value (e.g. host); see "Binding tokens to the host" below
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
  # :nonce_replayed, :plaintext_field, :mutation_expired, :too_fast, :no_js, :content
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

Style the honeypot by `class`, as above, rather than an `id` selector: when mutation
(`mutate:`) is on, the honeypot's own `name` is encrypted along with every other field's, so a
bot can't learn to skip it by its static name — and its `id` is deliberately left opaque too
(not subject to `Spamtrap.stable_ids`), since a stable id would give it away just as easily.

If you enable mutation via the `spamtrap:` option on `form_for`/`form_with` (the recommended
way — see [Field Name Mutation](#field-name-mutation)), field order doesn't matter. If instead
you pass `mutate:` directly to `f.spamtrap`, call it **before** any other field helper in the
form; fields rendered before it are not mutated.

### Honeypot styles

By default `f.spamtrap` renders a single hidden textarea. Some bots skip textareas, or skip
anything hidden with `display:none`, but still auto-fill visible-looking inputs and tick
checkboxes — `styles:` adds more decoy shapes to catch those:

```erb
<%= f.spamtrap :sarah_palin_walks_with_dinosaurs, styles: %i[textarea text checkbox] %>
```

`:textarea` renders the classic hidden `<textarea>`, named after the declared honeypot.
`:text` renders a hidden text `<input>` named `<honeypot>_input`; `:checkbox` renders a hidden,
unchecked checkbox named `<honeypot>_check`. All requested styles share the same hiding
attributes (`tabindex="-1"`, `autocomplete="off"`, `aria-hidden="true"`, `style="display:none"`),
and all are encrypted along with every other field when mutation is on. The controller checks
all three derived names regardless of which styles were actually rendered, so changing `styles:`
later never leaves an old decoy unchecked. The derived names are on the strict-mutation
allowlist automatically — you never need to add them to `Spamtrap.allowed_params`.

Set a default for every form with `Spamtrap.honeypot_styles = %i[textarea text checkbox]` in
the initializer, override per render with `styles:` on `f.spamtrap`, or via
`form_with model: @comment, spamtrap: { styles: %i[textarea text checkbox] }`.

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
- `:too_fast` — the nonce itself checked out, but the render timestamp is younger than
  `Spamtrap.min_fill_time`; see [Minimum fill time](#minimum-fill-time).

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

`nonce_bind_ip` can also be set per action and per render, overriding the global default —
but the view and the controller must agree, or a legitimate submission is rejected as
`:nonce_invalid`:

```ruby
spamtrap :field, nonce: true, nonce_bind_ip: :prefix, only: %i[create]
```

```erb
<%= f.spamtrap :field, nonce: true, nonce_bind_ip: :prefix %>
```

or via `form_with`:

```ruby
form_with model: @comment, spamtrap: { nonce: true, nonce_bind_ip: :prefix }
```

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

### Logging and `filter_parameters`

Rails writes a request's parameters to the log before any `before_action` runs, so it sees
the encrypted names, and name-based entries in `config.filter_parameters` (`:email`,
`:passw`, …) never match them. Spamtrap closes that gap by appending a filter block to
`config.filter_parameters`. On a request carrying `spamtrap_timestamp`, the block decrypts
each encrypted name and applies your app's own filters to the real name, so a mutated
`comment[email]` is logged as `[FILTERED]` and a mutated `comment[body]` still appears. There
is no separate list to maintain: whatever `config.filter_parameters` holds, including
filters added later, is what applies.

- `token_context` is unknown at that point (it often depends on state a `before_action` sets),
  so the block decrypts without checking the GCM tag. The unverified name is used only to
  decide whether to mask a value the client itself sent, never to read params.
- Dotted filters such as `"credit_card.number"` work too. Only field names are mutated, never
  the object or `fields_for` names around them, so the block rebuilds the field's real path
  and runs the filters against it, leaving out array positions as Rails does.
- When one render's `fields_for` children share a token (the same field name under several
  parents), the value is masked if a filter matches any of those paths.
- Cost: a block in `filter_parameters` makes Rails pass it every leaf parameter it filters.
  The block returns straight away on requests without `spamtrap_timestamp`. On requests with
  one, it indexes the params once and decrypts only keys shaped like tokens.

Set `Spamtrap.filter_parameters = false` to switch it off. The block stays installed but does
nothing.

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

## Minimum fill time

`Spamtrap.min_fill_time` (default `1`, seconds) rejects a submission whose verified render
timestamp is less than that many seconds old, with `reason: :too_fast`. A scripted poster
typically submits within milliseconds of fetching the page; one second is generous for a human,
who has to notice the form, move to it, and type.

It only applies when `nonce` or `mutate` is on — those are what bind `spamtrap_timestamp` into
something a submission can't forge (the nonce HMAC, or the mutation AAD), which is what makes
the timestamp trustworthy enough to check. Honeypot-only forms have no verified timestamp, so
`min_fill_time` has no effect on them. The check runs after the nonce HMAC is verified, so a
forged or stale timestamp is reported as `:nonce_invalid`/`:nonce_expired` rather than
`:too_fast`, and before a `:single_use` nonce is recorded, so a submission trapped as too fast
can be sent again from the same page once enough time has passed.

Set `false` or `0` to disable it globally:

```ruby
Spamtrap.min_fill_time = false
```

Or override it per action, like any other option:

```ruby
spamtrap :field, nonce: true, min_fill_time: 3, only: %i[create]
```

## JavaScript proof of presence

`js_proof: true` adds a hidden `spamtrap_js` field, plus an inline script that fills it in as
the page is parsed. A submission missing the field, or with the wrong value, is trapped with
`reason: :no_js`.

```ruby
spamtrap :sarah_palin_walks_with_dinosaurs, js_proof: true, only: %i[create update]
```

```erb
<%= f.spamtrap :sarah_palin_walks_with_dinosaurs, js_proof: true %>
```

Enable it globally with `Spamtrap.js_proof = true`, or via `form_with ... spamtrap: {
js_proof: true }`, the same as any other option.

**What this stops, and what it doesn't.** It stops a client that never executes JavaScript at
all — most scripted form posters. It does **not** stop a headless browser, which executes the
page's script like any real one. The value is present in the page source (reversed, as
obfuscation only, not encryption), so a bot that bothers to parse the inline script can compute
it itself. It's off by default because it's the one check here that excludes real users —
anyone with JavaScript disabled or blocked is rejected along with the bots.

The token is bound to the render timestamp and expires after `nonce_timeout`. With `nonce` or
`mutate` also on, that timestamp is itself verified (HMAC or mutation AAD); without either, it's
merely bounded by age, since nothing stops a submission from claiming an arbitrary timestamp.

**Content Security Policy.** The inline script is emitted via `javascript_tag(nonce: true)`, so
an app with a CSP nonce generator configured (`config.content_security_policy_nonce_generator`)
gets the nonce attribute automatically and needs no further change. An app with a strict CSP
and no nonce generator configured must add one, or the inline script will be blocked and
`js_proof` will trap every submission.

**Turbo.** The script runs as the page is parsed, so it works on a full page load and on a
Turbo Drive visit. A form rendered inside a Turbo Frame response will **not** run it, unless
your app re-executes scripts delivered inside frames — don't enable `js_proof` for a
frame-rendered form unless you've verified your app does that.

## Content hook

`Spamtrap.suspicious_if` (or per-action `suspicious_if:`) plugs your own spam-filtering logic
into the same trap machinery as the built-in checks — the same trap response, `on_trap`
callback, and `trap.spamtrap` instrumentation — without spamtrap trying to guess what "spammy"
means for your form. It runs last, after every other check has passed, and a truthy return
traps the submission with `reason: :content`.

```ruby
spamtrap :comment, only: :create,
         suspicious_if: ->(params) { params[:comment][:body].to_s.scan('http').size > 2 }
```

The callable is dispatched the same way as `on_trap` (see [Trap callback](#trap-callback-on_trap)):
a bare positional argument receives just `params`, or declare `params:`, `request:`, and/or
`controller:` as keywords to receive only what you ask for. An exception raised inside it is
logged and treated as *not* suspicious — a bug in your own heuristic must not end up trapping
every legitimate visitor.

Set it globally in the initializer, or override per action:

```ruby
Spamtrap.suspicious_if = ->(params) { params[:comment][:body].to_s.scan('http').size > 2 }
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
full-page submission. The reasons a human can plausibly hit — the ones worth a `default`
branch like this rather than a silent `:head` — are `:too_fast` (a very quick submission,
such as a browser autofill-and-send), `:nonce_expired`, `:mutation_expired`, `:nonce_invalid`
(most often an IP change between page load and submit), `:nonce_replayed` (a double
submit under `nonce: :single_use`), and `:no_js` (JavaScript disabled or blocked, under
`js_proof`).

## Instrumentation and rate limiting

Every trap publishes an `ActiveSupport::Notifications` event, `trap.spamtrap`, before `on_trap`
is called — use it for metrics or logging without touching `on_trap` at all:

```ruby
ActiveSupport::Notifications.subscribe('trap.spamtrap') do |event|
  # event.payload: reason, honeypot, controller, action, ip, request
  StatsD.increment('spamtrap.triggered', tags: ["reason:#{event.payload[:reason]}"])
end
```

`Spamtrap.throttle_key(request)` returns `"spamtrap:<ip>"`, with the IP normalised the same way
the nonce binds it (`Spamtrap.normalize_ip`, honouring `Spamtrap.nonce_bind_ip`) — use it to key
a rate limit to one client without reimplementing that normalisation yourself.

### Rack::Attack

Count trips in a `trap.spamtrap` subscriber, then block once a client trips it too often:

```ruby
ActiveSupport::Notifications.subscribe('trap.spamtrap') do |event|
  key = "#{Spamtrap.throttle_key(event.payload[:request])}:trips"
  Rails.cache.increment(key, 1, expires_in: 1.hour)
end

Rack::Attack.blocklist('spamtrap repeat offenders') do |request|
  Rails.cache.read("#{Spamtrap.throttle_key(request)}:trips").to_i >= 5
end
```

This needs a real, shared cache store — as with `nonce: :single_use` (see
[Single-use nonces](#single-use-nonces)), `ActiveSupport::Cache::NullStore` (Rails'
test-environment default) never actually records a trip.

### Rails' built-in `rate_limit`

Rails 8's `rate_limit` is a blunter alternative: no subscriber needed, but it throttles *every*
submission from a client prefix, not just trapped ones:

```ruby
class CommentsController < ApplicationController
  rate_limit to: 10, within: 1.hour, by: -> { Spamtrap.throttle_key(request) }, only: :create
end
```

## Rotating secret_key_base

`Spamtrap.secret_key_base` (defaults to `Rails.application.secret_key_base`) is the secret new
tokens and nonces are minted and verified against; `Spamtrap.previous_secret_key_base` (default
`nil`) is tried second on a mismatch. Set it for one timeout window after rotating
`secret_key_base`, and forms that were already rendered under the old secret keep verifying
until they'd have expired on their own anyway:

```ruby
# config/initializers/spamtrap.rb
Spamtrap.secret_key_base          = ENV['SPAMTRAP_SECRET']
Spamtrap.previous_secret_key_base = ENV['SPAMTRAP_PREVIOUS_SECRET'] # remove once nonce_timeout/mutation_timeout has passed
```

Keys are derived from each secret once per process (HKDF), not on every request.

## Binding tokens to the host (multi-tenant apps)

An app serving many hostnames from one `secret_key_base` shares its keys across all of them —
a nonce, mutation token, or `js_proof` value minted while rendering a form on `a.example` also
verifies on `b.example`. `Spamtrap.token_context` closes that gap by mixing a value you derive
from the request into every token:

```ruby
# config/initializers/spamtrap.rb
Spamtrap.token_context = ->(request) { request.host }
```

It's off (`nil`) by default, so the token format is unchanged for apps that don't set it — every
existing token keeps verifying exactly as before. Once set, a token minted on one host and
submitted from another fails the same check it always would have, with no new trap reason:
`nonce_invalid` for the nonce, `plaintext_field` (strict) or an unmapped field (`:lenient`) for
mutation, and `no_js` for `js_proof`.

**Caution:** don't enable this if a form can legitimately be rendered on one hostname and posted
to another — e.g. `www.example.com` serving the form for `app.example.com` to submit to, or an
app sitting behind a proxy that rewrites the `Host` header before it reaches Rails. In either
case `request.host` differs between render and submission for entirely legitimate traffic, and
every one of those submissions would be rejected. Use a context both sides agree on instead, such
as the tenant id:

```ruby
Spamtrap.token_context = ->(request) { Current.tenant_id }
```

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

- `spamtrap_params(honeypot:, ip: '0.0.0.0', nonce: false, mutate: false, js_proof: false, at: Time.now.to_i - 5, bind_ip: Spamtrap.nonce_bind_ip, fields: nil, context: nil)` —
  the params hash a protected action needs: the empty honeypot field, plus whatever
  `spamtrap_timestamp`/nonce/`js_proof` fields the declared options require. `fields:` is
  merged in — through `spamtrap_mutate` first when `mutate:` is truthy, unchanged otherwise —
  so one call builds the whole POST.
- `spamtrap_token(name, timestamp, context: nil)` — encrypts a real field name into the same kind
  of mutation token the view helper renders, for posting to a `mutate:`-protected action.
- `spamtrap_decrypt(token, timestamp, context: nil)` — the reverse, for asserting on a token your
  app captured.
- `spamtrap_mutate(hash, at:, context: nil)` — encrypts every field name in a whole params hash
  the way the form builder renders them, so it round-trips through a `mutate:`-protected action
  without hand-building a token per field. Object/`fields_for` container names (a key whose value
  is a Hash, or an Array of Hashes) are left plaintext and recursed into; every other key —
  including one whose value is an array of scalars — is encrypted, with a trailing
  multi-parameter suffix like `published_on(1i)` preserved after the token.
- `spamtrap_nonce_params(honeypot:, ip:, at: Time.now.to_i - 5, nonce_id: SecureRandom.hex(16), bind_ip: Spamtrap.nonce_bind_ip, context: nil)` —
  just the nonce fields, if you need them without the honeypot key.
- `spamtrap_js_param(honeypot:, at:, context: nil)` — just the `spamtrap_js` field, at the value
  the inline script would have written for a page rendered at `at`, if you need it without the
  rest of `spamtrap_params`.

`at:` defaults to five seconds in the past on both, so a token built this way already clears
`Spamtrap.min_fill_time`'s default 1-second floor (see [Minimum fill time](#minimum-fill-time))
without you having to think about it. `bind_ip:` lets you build params for an action declared
with a non-default `nonce_bind_ip:` (see [IP binding](#ip-binding)). `context:` lets you build
params matching an app that has set `Spamtrap.token_context` (see
[Binding tokens to the host](#binding-tokens-to-the-host-multi-tenant-apps)) — pass the same
value your `token_context` callable would have returned for the request under test.

```ruby
class CommentsControllerTest < ActionController::TestCase
  def test_create_with_mutation_and_nonce
    ts = Time.now.to_i - 5
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

If your own test helpers mint a `spamtrap_timestamp` directly instead of going through
`spamtrap_params`/`spamtrap_nonce_params` — e.g. stamping `Time.now.to_i` straight into a
fixture — either backdate it by a few seconds the same way, or set
`Spamtrap.min_fill_time = false` in your test environment; otherwise a request built and posted
within the same second as `Time.now` trips `:too_fast`.

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
