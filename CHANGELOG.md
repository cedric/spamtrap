# Changelog

All notable changes to this project will be documented in this file.

## [0.4.1] - 2026-09-27

### Added
- `Spamtrap.min_fill_time` (default `1` second) — rejects a submission whose verified render
  timestamp is younger than this, with `reason: :too_fast`. Applies only when `nonce` or
  `mutate` is on (those are what make the timestamp trustworthy) and checks after the nonce, so
  a forged timestamp still reports as `:nonce_invalid`. Also settable per action via
  `min_fill_time:`.
- Every trap now publishes an `ActiveSupport::Notifications` event, `trap.spamtrap`, with
  payload keys `reason`, `honeypot`, `controller`, `action`, `ip`, and `request`, before
  `on_trap` runs.
- `Spamtrap.throttle_key(request)` — `"spamtrap:<ip>"`, IP-normalised the same way the nonce
  binds it (honouring `nonce_bind_ip`), for keying `Rack::Attack` or Rails' `rate_limit` off
  `trap.spamtrap` events.
- `Spamtrap.secret_key_base` (defaults to the app's own) and
  `Spamtrap.previous_secret_key_base` (default `nil`) — tokens and nonces are minted with the
  current secret; verification tries the current secret, then the previous one, so setting
  `previous_secret_key_base` for one timeout window after rotating `secret_key_base` keeps
  in-flight forms valid.
- `ActionController::API` subclasses can now use the `spamtrap` macro, installed via the same
  Railtie as `ActionController::Base`.
- `nonce_bind_ip:` is now accepted per declaration — by the `spamtrap` macro, by `f.spamtrap`,
  and via `form_with ... spamtrap: { nonce_bind_ip: :prefix }` — not just as a global default.
- The honeypot field's own `name` is now encrypted along with every other field when mutation
  is on, so a bot can't learn to skip it by its static name. Its `id` is deliberately left
  opaque (not subject to `Spamtrap.stable_ids`), since a stable id would give it away just as
  easily.
- `Spamtrap::TestHelper#spamtrap_params` and `#spamtrap_nonce_params` accept `bind_ip:`.

### Changed
- `Spamtrap.min_fill_time` defaults to `1` second, so a submission received less than a second
  after its verified render is now trapped with `reason: :too_fast`. This only affects forms
  using `nonce` or `mutate` — honeypot-only forms are unaffected — and can be disabled globally
  with `Spamtrap.min_fill_time = false` or per action with `min_fill_time: false`.
  `Spamtrap::TestHelper#spamtrap_params`/`#spamtrap_nonce_params` now default `at:` to five
  seconds in the past so existing tests using them keep passing unmodified; a test suite that
  mints its own timestamps as `Time.now` should backdate them or set
  `Spamtrap.min_fill_time = false` in its test environment.

## [0.4.0] - 2026-09-27

### Breaking
- The nonce and mutation token formats have changed (see Security below). Forms rendered by
  0.3.x are rejected once 0.4.0 is deployed, until each page is re-rendered — because the old
  tokens don't verify under the new format. Deploy at low-traffic times where possible, and
  consider setting `trap_response` (new in this release) to something other than the silent
  `:head` default so affected users get visible feedback instead of a submission that appears
  to vanish.
- `on_trap`'s `reason:` value of `:nonce` has been split into `:nonce_missing`,
  `:nonce_expired`, `:nonce_invalid`, and `:nonce_replayed`. Callbacks that pattern-match on
  `reason: :nonce` need updating to match the new set.
- The `spamtrap_mutation_salt` hidden field has been removed. It's replaced by
  `spamtrap_timestamp`, which now serves as the shared render timestamp for both mutation and
  the nonce.
- The view helper now also emits a `spamtrap_nonce_id` hidden field whenever `nonce:` is
  enabled. Any code that hand-builds spamtrap form fields instead of using `f.spamtrap` needs
  to add it.
- `mutate: true` is now strict by default (equivalent to `mutate: :strict`); `:lenient`
  restores the old remap-only behaviour. Apps using `mutate: true` that post custom top-level
  params must add them to `Spamtrap.allowed_params` or switch to `:lenient`.
- The gem's runtime dependency has changed from `rails` to `actionpack`, `actionview`, and
  `railties` (`>= 7.2`, `< 9`). Rails 7.0 and 7.1 are no longer supported. Apps that relied on
  the gem pulling in `rails` transitively must depend on it themselves — nearly all Rails apps
  already do.
- The honeypot textarea now renders with `tabindex="-1"`, `autocomplete="off"`,
  `aria-hidden="true"`, and an inline `style="display:none"` by default. Apps whose CSS
  depended on the textarea being visible in the DOM tree for layout are unaffected, but an app
  that deliberately kept the honeypot focusable must now pass `tabindex: nil` to restore that.
- `mutate: true`/`:strict` now allowlists three captcha widgets' response params by default —
  `g-recaptcha-response`, `h-captcha-response`, `cf-turnstile-response` — since the widget
  injects them as plaintext and the app can't encrypt them. Any other widget's plaintext param
  still needs adding to `Spamtrap.allowed_params`.

### Security
- **Shared GCM IV.** Every mutated field name in a render previously reused the same AES-GCM
  IV under one key — a specific misuse of AES-GCM that weakens its confidentiality
  guarantees. Each field now gets its own random IV.
- **Non-expiring mutation tokens.** A mutated field-name token never expired, so a token
  captured once stayed valid indefinitely. Tokens now embed the render timestamp as
  associated data and are rejected once `mutation_timeout` has passed.
- **Plaintext bypass of mutation.** `mutate: true` hid field names in the rendered HTML, but
  the controller accepted a submitted plaintext field name exactly like any other param, so a
  bot that already knew the field names was never actually blocked. `mutate: :strict` is a
  new mode that rejects any submitted key that isn't a valid mutation token.
- **Nonce replay and unbounded future timestamps.** The nonce was a deterministic HMAC with
  no mechanism to detect a repeated submission, and no check on how far a timestamp could sit
  in the future. `nonce: :single_use` now rejects a repeated `nonce_id`, and a timestamp more
  than `nonce_skew` seconds in the future is rejected as `:nonce_invalid`.

### Added
- `nonce: :single_use` — rejects a replayed nonce id, recorded in `Spamtrap.nonce_store`
  (defaults to `Rails.cache`; needs a real shared cache store in production).
- `mutate: :strict` — traps any submitted field name that isn't a valid mutation token.
- `Spamtrap.allowed_params` — extra top-level param names a `:strict` action accepts
  unencrypted.
- `Spamtrap.trap_response` — configures the response sent to a trapped submission: `:head`
  (default), `:no_content`, `:unprocessable`, `:redirect_back`, a callable, or a `Hash` keyed
  by trap reason with a `:default` key. Also settable per action via `trap_response:`.
- `Spamtrap.mutation_timeout` — how long a mutation token stays valid; defaults to
  `Spamtrap.nonce_timeout`.
- `Spamtrap.nonce_skew` — how far a submitted timestamp may sit in the future before it's
  rejected.
- `Spamtrap.nonce_store` — where `nonce: :single_use` records seen nonce ids.
- `on_trap` now optionally receives `controller:`, `honeypot:`, and `params:` in addition to
  `reason:` and `request:`; only the keywords a given callback declares are passed, so
  existing `->(reason:, request:) { ... }` callbacks are unaffected.
- The field-name remap now recurses into arrays of `fields_for` builders, not just single
  nested objects.
- GitHub Actions CI, replacing the old Travis configuration. The matrix covers Ruby 3.4 and 4.0 against Rails 7.2 to 8.1.
- `Spamtrap.enabled` (default `true`) — global kill switch; `false` skips every check
  (honeypot, nonce, mutation), for test environments.
- `Spamtrap.nonce_bind_ip` — `true` (default, binds to the full client IP), `:prefix` (binds
  to the /24 IPv4 or /48 IPv6 network, tolerating mobile handoffs and CGNAT; an IPv4-mapped
  IPv6 address is masked as IPv4 first, not folded into one /48), or `false` (not bound at
  all).
- `mutate: :lenient` — the old remap-only behaviour, now that `mutate: true` traps plaintext
  fields by default.
- `spamtrap/test_helper` (`Spamtrap::TestHelper`, opt-in via `require 'spamtrap/test_helper'`)
  — `spamtrap_params`, `spamtrap_token`, `spamtrap_decrypt`, and `spamtrap_nonce_params` for
  building valid params in your own app's tests.
- `f.spamtrap` now renders `tabindex="-1"`, `autocomplete="off"`, `aria-hidden="true"`, and an
  inline `style="display:none"` by default, so hiding the honeypot no longer requires app CSS;
  any of these can be overridden, and `style: nil` removes the inline hide.
- `spamtrap:` option on `form_with`/`form_for` (e.g.
  `form_with model: @comment, spamtrap: { mutate: true, nonce: true }`) mints the shared
  render timestamp at builder construction, so `f.spamtrap` no longer needs to be called
  before the fields it protects.
- Mutation now covers every `FormBuilder` field helper, including `radio_button`,
  `phone_field`, `datetime_field`, `time_zone_select`, `weekday_select`,
  `collection_check_boxes`, `collection_radio_buttons`, `date_select`, `time_select`,
  `datetime_select` (multi-parameter names such as `field(1i)` are remapped), and
  `rich_text_area` when Action Text is loaded.
- Mutated fields keep `id`/label `for` attributes derived from the real field name instead of
  the encrypted one, so CSS, Stimulus targets, and autofill keep working; opt out with
  `Spamtrap.stable_ids = false`. `field_with_errors` wrapping works on mutated fields again.
- `Spamtrap::NoRequestError` — raised when nonce fields are rendered without a request
  (mailers, `ApplicationController.render` outside a request).
- `Spamtrap::Controller::CAPTCHA_PARAMS` — the three captcha response params allowlisted by
  default under strict mutation.
- `spamtrap_mutate(hash, at:)` on `Spamtrap::TestHelper` — encrypts every field name in a
  whole params hash the way the form builder renders them, so it round-trips through a
  `mutate:`-protected action without hand-building a token per field.
- `fields:` keyword on `spamtrap_params` — merges in a fields hash, through `spamtrap_mutate`
  first when `mutate:` is truthy, so a single call builds the whole POST for a protected
  action's test.

### Changed
- Each field name is encrypted to a single token per render, shared with `fields_for` children.
  Indexless array params such as `items[][name]` need the repeated key to split into separate
  records; with a fresh token per child builder, every record was merged into one.
- An expired mutation render (older than `mutation_timeout`, or too far in the future) now
  traps as `reason: :mutation_expired` in `:lenient` mode as well as `:strict` — previously
  only `:strict` checked it, so a stale-but-decryptable `:lenient` submission was silently
  accepted. In both modes, every field is now decrypted and remapped to its real name before
  the trap fires, with no additional staleness bound on that remap, so `on_trap` and a
  `trap_response` callable can re-render the form with what the user actually typed instead of
  an empty one.
- The nonce's HMAC key is now derived via HKDF from `secret_key_base` (rather than using
  `secret_key_base` directly) and the digest is now bound to the honeypot field name, so a
  valid nonce for one honeypot can't be replayed against another.
- Removed Travis and Rails 3/4 compatibility scaffolding.
- Spamtrap now installs itself via `Spamtrap::Railtie` from `on_load` hooks instead of
  patching `ActionController::Base`/`FormBuilder` at require time, so the patches land after
  app initializers run rather than forcing Action Controller to load first. Outside a Rails
  app, call `Spamtrap.install!` yourself after Action Controller and Action View are loaded.

## [0.3.5] - 2026-07-08

### Fixed
- Arity error in `FormBuilderMutation#label` when a subclass or custom form builder passes an explicit `nil` as the text argument. The label now correctly treats explicit `nil` the same as an omitted text argument and resolves the display text from the real field name.

## [0.3.4] - 2026-07-08

### Fixed
- Labels rendered with `mutate: true` were displaying the encrypted field name ciphertext as their visible text. The label helper now resolves the display text from the **real** field name before substituting the encrypted form, following Rails' standard resolution order:
  1. Explicit text argument (kept as-is)
  2. `activerecord.attributes.Model.field` I18n translation (ActiveRecord models)
  3. `helpers.label.object_name.field` I18n scope (plain objects)
  4. `humanize` fallback
  The `for` attribute still uses the encrypted name so it correctly associates with the mutated input.

## [0.3.3] - 2026-07-08

### Fixed
- `NoMethodError` raised in `FormBuilderMutation` when `mutate: true` is used with model-backed forms (e.g. `form_for @record`). The mutation module now correctly reads the model's current field value to populate the encrypted input, rather than calling a method that did not exist on the encrypted field name.

## [0.3.2] - 2026-07-08

### Added
- `on_trap` callback hook — invoked whenever the spamtrap fires (honeypot triggered or nonce invalid), giving consuming applications a first-class signal for logging, metrics, rate-limiting, or any other custom behaviour.

  Configure globally in an initializer:

  ```ruby
  Spamtrap.on_trap = lambda do |reason:, request:|
    Rails.logger.warn "[Spamtrap] #{reason} fired from #{request.remote_ip}"
    StatsD.increment('spamtrap.triggered', tags: ["reason:#{reason}"])
  end
  ```

  Or override per declaration:

  ```ruby
  spamtrap :field, only: :create, on_trap: ->(reason:, request:) {
    Honeybadger.notify("Spamtrap fired", context: { reason:, ip: request.remote_ip })
  }
  ```

  `reason:` is `:honeypot` or `:nonce`. Exceptions raised inside the callback are rescued and logged; a broken callback never prevents the silent `head 200` discard. Fully backwards compatible — no behaviour change when `on_trap` is not set.

## [0.3.1] - 2026-07-08

### Added
- Global configuration defaults for `nonce`, `nonce_timeout`, and `mutate` settable via an initializer. Per-controller and per-action options take precedence, including an explicit `false` overriding a global `true`. Globals are resolved at request time so changes take effect without a server restart.

  ```ruby
  # config/initializers/spamtrap.rb
  Spamtrap.nonce         = true
  Spamtrap.nonce_timeout = 15.minutes
  Spamtrap.mutate        = true
  ```

## [0.3.0] - 2026-07-08

### Added
- **Cryptographic nonce** — HMAC-SHA256 token (timestamp + client IP + `secret_key_base`) prevents replay attacks. Expired or tampered submissions are silently discarded. Timeout defaults to 30 minutes and is configurable globally via `Spamtrap.nonce_timeout` or per-action via `nonce_timeout:`.
- **Field name mutation** — AES-128-GCM encrypts all form field names with a random per-render salt. Field names are unrecognizable in HTML source and change on every page load. The controller decrypts and remaps params transparently before the action runs; no changes to `params.require(...).permit(...)` are needed. Mutation salt propagates automatically to `fields_for` child builders.
- `lib/spamtrap/crypto.rb` — shared `Spamtrap::Crypto` module providing AES-128-GCM encrypt/decrypt primitives, used by both the controller and the form builder.
- Full test suite (19 tests) replacing the placeholder `assert true`.

### Changed
- Requires Rails `>= 7.0` and Ruby `>= 3.0.0`.

## [0.2.0] - 2026-02-12

### Changed
- Updated for Rails 7+ compatibility.
- Cleaned up README copy and documentation.

## [0.1.1] - 2018-09-05

### Changed
- Replace deprecated `render(nothing: true)` with `head :ok` for Rails 4+ compatibility (via [tiegz](https://github.com/tiegz), PR #2).
- Updated gem dependencies.

### Added
- Optional block argument on the `spamtrap` controller macro for advanced use cases such as swapping the honeypot with a real form parameter at runtime (added 2011, shipped in this release).

## [0.0.3] - 2010-10-21

### Fixed
- Fixed rake task dependency ordering.

### Added
- Added gem dependencies and load path configuration.

## [0.0.2] - 2010-10-21

### Added
- Rake task descriptions and `gem:` namespace for build and release tasks.
- Warning log output with client IP when honeypot is triggered.

## [0.0.1] - 2010-10-20

### Added
- Initial release.
- `spamtrap` controller macro — registers a `before_action` that silently discards submissions where the named honeypot field is non-empty, returning `200 OK`.
- `f.spamtrap` form builder helper — renders a hidden `<textarea>` honeypot field with a configurable CSS class.
