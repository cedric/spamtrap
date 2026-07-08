# Changelog

All notable changes to this project will be documented in this file.

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
