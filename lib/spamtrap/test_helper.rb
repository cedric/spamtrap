require 'securerandom'
require 'spamtrap/crypto'
require 'spamtrap/controller'

# Not required by lib/spamtrap.rb: apps opt in with `require 'spamtrap/test_helper'`
# and `include Spamtrap::TestHelper` in their own test cases.
module Spamtrap
  module TestHelper
    # Exposes Crypto's private methods so tests can mint/verify tokens without reimplementing them.
    class TokenHelper
      include Spamtrap::Crypto
      public :spamtrap_encrypt_field, :spamtrap_decrypt_field, :spamtrap_nonce_digest
    end

    def spamtrap_token(name, timestamp)
      TokenHelper.new.spamtrap_encrypt_field(name.to_s, timestamp.to_s)
    end

    def spamtrap_decrypt(token, timestamp)
      TokenHelper.new.spamtrap_decrypt_field(token, timestamp.to_s)
    end

    # at defaults 5s in the past so Spamtrap.min_fill_time (default 1s) doesn't trap these tokens.
    def spamtrap_nonce_params(honeypot:, ip:, at: Time.now.to_i - 5, nonce_id: SecureRandom.hex(16), bind_ip: Spamtrap.nonce_bind_ip)
      {
        spamtrap_timestamp: at,
        spamtrap_nonce_id:  nonce_id,
        spamtrap_nonce:     TokenHelper.new.spamtrap_nonce_digest(at, ip, honeypot, nonce_id, bind_ip: bind_ip)
      }
    end

    # Builds the params hash an app's own controller test merges into its `post` params:
    # the honeypot field, plus whatever spamtrap_timestamp/nonce fields the declared
    # options require, so the request clears the whole gauntlet in one call. `fields:`
    # is merged in as-is, or through spamtrap_mutate first when `mutate:` is truthy.
    # at defaults 5s in the past so Spamtrap.min_fill_time (default 1s) doesn't trap these tokens.
    def spamtrap_params(honeypot:, ip: '0.0.0.0', nonce: false, mutate: false, at: Time.now.to_i - 5, bind_ip: Spamtrap.nonce_bind_ip, fields: nil)
      params = {}
      if nonce
        params.merge!(spamtrap_nonce_params(honeypot: honeypot, ip: ip, at: at, bind_ip: bind_ip))
      elsif mutate
        params[:spamtrap_timestamp] = at
      end
      params[honeypot] = ''
      params.merge!(mutate ? spamtrap_mutate(fields, at: at) : fields) if fields
      params
    end

    # Encrypts every field name in `hash` exactly the way the form builder renders them, so
    # the result round-trips through spamtrap_remap_hash under a strict action. A key whose
    # value is a Hash, or an Array of Hashes, is a container (object/fields_for name) and
    # stays plaintext with its value recursed into; every other key, including one whose
    # value is an Array of scalars, is a field and gets encrypted as a whole. A trailing
    # multi-parameter suffix like "(1i)" is preserved after the token. Top-level keys in
    # FRAMEWORK_PARAMS/CAPTCHA_PARAMS are left alone. Accepts string or symbol keys, returns
    # string keys.
    def spamtrap_mutate(hash, at:)
      spamtrap_mutate_hash(hash, at, {}, top_level: true)
    end

    private

    # tokens: one token per field name, as the form builder does, so array records stay separate.
    def spamtrap_mutate_hash(hash, at, tokens, top_level: false)
      allowlist = Spamtrap::Controller::FRAMEWORK_PARAMS + Spamtrap::Controller::CAPTCHA_PARAMS

      hash.each_with_object({}) do |(key, value), memo|
        key_str = key.to_s

        if top_level && allowlist.include?(key_str)
          memo[key_str] = value
        elsif spamtrap_mutate_container?(value)
          memo[key_str] = spamtrap_mutate_container(value, at, tokens)
        else
          base, suffix = key_str.match(/\A(.+?)(\(\d+[a-z]\))\z/)&.captures
          name = base || key_str
          memo["#{tokens[name] ||= spamtrap_token(name, at)}#{suffix}"] = value
        end
      end
    end

    def spamtrap_mutate_container?(value)
      value.is_a?(Hash) || (value.is_a?(Array) && value.any? { |el| el.is_a?(Hash) })
    end

    def spamtrap_mutate_container(value, at, tokens)
      return spamtrap_mutate_hash(value, at, tokens) if value.is_a?(Hash)

      value.map { |el| el.is_a?(Hash) ? spamtrap_mutate_hash(el, at, tokens) : el }
    end
  end
end
