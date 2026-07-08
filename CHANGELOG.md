# Changelog

## [0.3.3] - 2026-07-08

### Fixed

- Field name mutation now works correctly with model-backed forms when `mutate: true`.
  Field helpers preserve pre-populated values without attempting model lookups on encrypted
  field names.

## [0.3.2] - 2026-07-08

### Added

- `on_trap` callback hook — invoked whenever the spamtrap fires (honeypot field filled or
  invalid nonce), giving consuming applications a first-class signal for logging, metrics,
  rate-limiting, or any other custom behaviour.

  Configure globally in an initializer:

  ```ruby
  # config/initializers/spamtrap.rb
  Spamtrap.on_trap = lambda do |reason:, request:|
    # reason is :honeypot or :nonce
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

  Callback arguments:
  - `reason:` — `:honeypot` (hidden field was filled) or `:nonce` (HMAC nonce was missing,
    invalid, or expired)
  - `request:` — the `ActionDispatch::Request` object

  Exceptions raised inside the callback are rescued and logged; a broken callback never
  prevents the silent `head 200` discard.

  Fully backwards compatible — no behaviour change when `on_trap` is not set.

## [0.3.1] - 2025-01-01

- Field name mutation (`mutate:`) — AES-128-GCM encrypts all form field names on every page
  render; the controller remaps them back transparently. Propagates to nested `fields_for`
  builders automatically.
- Replay attack protection (`nonce:`) — HMAC-SHA256 token binding each submission to a
  timestamp and client IP, keyed with `secret_key_base`. Configurable timeout via
  `nonce_timeout`.
- Global configuration via `Spamtrap.nonce`, `Spamtrap.mutate`, and `Spamtrap.nonce_timeout`.
- Per-declaration options override globals, including explicit `false` to opt out of a
  globally enabled feature.
