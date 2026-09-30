# Spamtrap global configuration. Every option can be overridden per controller action or
# per render; an explicit value there always wins, including `false` over a global `true`.
# See https://github.com/cedric/spamtrap/ for the full guide.

# Honeypot

# Decoys f.spamtrap renders: any of :textarea, :text, :checkbox.
# Spamtrap.honeypot_styles = [:textarea]

# Require a hidden field that only an executing script fills in; excludes no-JS users.
# Spamtrap.js_proof = false

# Nonce

# false, true, or :single_use.
# Spamtrap.nonce = false

# Seconds; also caps mutation token age unless mutation_timeout is set.
# Spamtrap.nonce_timeout = 1800

# Seconds a submitted timestamp may sit in the future.
# Spamtrap.nonce_skew = 60

# true (full IP), :prefix (/24 IPv4 or /48 IPv6), or false (not bound).
# Spamtrap.nonce_bind_ip = true

# Where nonce: :single_use records seen nonce ids; defaults to the app's cache.
# Spamtrap.nonce_store = Rails.cache

# Mutation

# false, true/:strict (traps plaintext keys), or :lenient (remap only).
# Spamtrap.mutate = false

# Seconds; defaults to nonce_timeout.
# Spamtrap.mutation_timeout = nil

# Extra top-level param names a strict action accepts unencrypted.
# Spamtrap.allowed_params = []

# Whether mutated fields keep an id/for derived from the real field name.
# Spamtrap.stable_ids = true

# Apply config.filter_parameters to mutated field names, which the log otherwise shows unfiltered.
# Spamtrap.filter_parameters = true

# Fill time

# Minimum seconds between render and submission a human needs; false or 0 disables.
# Spamtrap.min_fill_time = 1

# Responses and callbacks

# How a trapped request responds: :head, :no_content, :unprocessable, :redirect_back,
# a callable, or a Hash keyed by trap reason.
# Spamtrap.trap_response = :head

# Optional callback invoked whenever the spamtrap fires.
# Spamtrap.on_trap = ->(reason:, request:) { }

# App-defined heuristic run after every other check; truthy result traps as :content.
# Spamtrap.suspicious_if = nil

# Keys

# The current HKDF source secret; defaults to the app's own so no setup is needed to opt in.
# Spamtrap.secret_key_base = nil

# Set during a rotation window so tokens minted under the old secret still verify/decrypt.
# Spamtrap.previous_secret_key_base = nil

# Binds tokens to a value derived from the request (e.g. host), for multi-tenant apps; off by default.
# Spamtrap.token_context = nil

# Testing

# Global kill switch; false skips every spamtrap check. Handy for test environments.
# Spamtrap.enabled = true
