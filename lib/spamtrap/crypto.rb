require 'base64'
require 'securerandom'
require 'ipaddr'

module Spamtrap
  module Crypto
    CIPHER    = 'aes-128-gcm'
    KEY_LEN   = 16
    NONCE_LEN = 12
    TAG_LEN   = 16

    TOKEN_DRAWS = 8 # see spamtrap_encrypt_field

    class << self
      # HKDF-derives {mutation:, nonce:} keys, memoised per secret at module level so each
      # request doesn't re-derive them; previous_secret_key_base is what keeps a rotation from
      # orphaning in-flight forms.
      def keys_for(secret)
        @keys_cache ||= {}
        @keys_cache[secret] ||= begin
          derived = {
            mutation: OpenSSL::KDF.hkdf(secret, salt: 'spamtrap-mutation', info: '', length: KEY_LEN, hash: 'SHA256'),
            nonce:    OpenSSL::KDF.hkdf(secret, salt: 'spamtrap-nonce',    info: '', length: 32,       hash: 'SHA256')
          }
          # Cap at the two most recent secrets so a test suite rotating secrets can't grow this unboundedly.
          @keys_cache.delete(@keys_cache.keys.first) while @keys_cache.size > 1
          derived
        end
      end

      # The name a mutated token decrypts to under each secret, skipping the tag and AAD check
      # because Rails filters params before token_context can be computed. Unverified: fit only
      # for deciding whether to mask a logged value, never for reading params.
      def unverified_field_names(token)
        raw = Base64.urlsafe_decode64(token)
        return [] unless raw.bytesize > NONCE_LEN + TAG_LEN

        [Spamtrap.secret_key_base, Spamtrap.previous_secret_key_base].compact.filter_map do |secret|
          cipher = OpenSSL::Cipher.new(CIPHER).decrypt
          cipher.key = keys_for(secret)[:mutation]
          cipher.iv  = raw[0, NONCE_LEN]
          name = cipher.update(raw[NONCE_LEN...-TAG_LEN]).force_encoding(Encoding::UTF_8)
          name if name.valid_encoding? # a wrong secret yields random bytes, rarely valid UTF-8
        end
      rescue ArgumentError
        []
      end
    end

    private

    # Appended only when context is non-nil, so the default AAD/message shape is unchanged.
    def spamtrap_aad(timestamp, context)
      context.nil? ? timestamp.to_s : "#{timestamp}:#{context}"
    end

    # A token the app's filter_parameters match as it stands (one containing otp or cvv, say) is
    # masked in the log before the real name is checked: 0.38% of draws per field under Rails'
    # generated list. So draw again. Capped because a filter matching every token would never stop.
    def spamtrap_encrypt_field(field_name, aad)
      token = nil
      TOKEN_DRAWS.times do
        token = spamtrap_encrypt_field_once(field_name, aad)
        break unless defined?(Spamtrap::ParameterFilter) && Spamtrap::ParameterFilter.masks_token?(token)
      end
      token
    end

    # aad binds the token to the render timestamp so it can't be replayed under a different one.
    def spamtrap_encrypt_field_once(field_name, aad)
      cipher = OpenSSL::Cipher.new(CIPHER)
      cipher.encrypt
      cipher.key = Spamtrap::Crypto.keys_for(Spamtrap.secret_key_base)[:mutation]
      cipher.iv  = iv = SecureRandom.bytes(NONCE_LEN)
      cipher.auth_data = aad.to_s
      ct = cipher.update(field_name.to_s) + cipher.final
      Base64.urlsafe_encode64(iv + ct + cipher.auth_tag(TAG_LEN), padding: false)
    end

    # Tries the current secret, then the previous one (rotation window), before giving up.
    def spamtrap_decrypt_field(token, aad)
      raw = Base64.urlsafe_decode64(token)
      return nil unless raw.bytesize > NONCE_LEN + TAG_LEN

      [Spamtrap.secret_key_base, Spamtrap.previous_secret_key_base].compact.each do |secret|
        result = spamtrap_decrypt_raw(raw, aad, secret)
        return result if result
      end
      nil
    rescue ArgumentError
      nil
    end

    def spamtrap_decrypt_raw(raw, aad, secret)
      iv  = raw[0, NONCE_LEN]
      ct  = raw[NONCE_LEN...-TAG_LEN]
      tag = raw[-TAG_LEN..]
      cipher = OpenSSL::Cipher.new(CIPHER)
      cipher.decrypt
      cipher.key       = Spamtrap::Crypto.keys_for(secret)[:mutation]
      cipher.iv        = iv
      cipher.auth_data = aad.to_s
      cipher.auth_tag  = tag
      (cipher.update(ct) + cipher.final).to_sym
    rescue OpenSSL::Cipher::CipherError
      nil
    end

    # Value the inline script writes into spamtrap_js. Visible in the page source by design:
    # it proves a script ran, not that the client is honest.
    def spamtrap_js_digest(timestamp, honeypot, secret: Spamtrap.secret_key_base, context: nil)
      key = Spamtrap::Crypto.keys_for(secret)[:nonce]
      message = "js:v1:#{timestamp}:#{honeypot}"
      message += ":#{context}" unless context.nil? # appended only when present so the default digest is unchanged
      OpenSSL::HMAC.hexdigest('SHA256', key, message)
    end

    # v1: versions the message for future key rotation; honeypot scopes a token to one form.
    # secret defaults to current but the caller retries with previous_secret_key_base on mismatch.
    def spamtrap_nonce_digest(timestamp, ip, honeypot, nonce_id, bind_ip: Spamtrap.nonce_bind_ip, secret: Spamtrap.secret_key_base, context: nil)
      key = Spamtrap::Crypto.keys_for(secret)[:nonce]
      message = "v1:#{timestamp}:#{Spamtrap.normalize_ip(ip, bind_ip)}:#{honeypot}:#{nonce_id}"
      message += ":#{context}" unless context.nil? # appended only when present so the default digest is unchanged
      OpenSSL::HMAC.hexdigest('SHA256', key, message)
    end
  end
end
