require 'base64'

module Spamtrap
  module Crypto
    CIPHER    = 'aes-128-gcm'
    KEY_LEN   = 16
    NONCE_LEN = 12
    TAG_LEN   = 16

    private

    def spamtrap_crypto_key
      @spamtrap_crypto_key ||= OpenSSL::KDF.hkdf(
        Rails.application.secret_key_base,
        salt:   'spamtrap-mutation',
        info:   '',
        length: KEY_LEN,
        hash:   'SHA256'
      )
    end

    def spamtrap_encrypt_field(field_name, salt_bytes)
      cipher = OpenSSL::Cipher.new(CIPHER)
      cipher.encrypt
      cipher.key = spamtrap_crypto_key
      cipher.iv  = salt_bytes
      ct = cipher.update(field_name.to_s) + cipher.final
      Base64.urlsafe_encode64(ct + cipher.auth_tag(TAG_LEN), padding: false)
    end

    def spamtrap_decrypt_field(token, salt_bytes)
      raw = Base64.urlsafe_decode64(token)
      return nil if raw.bytesize <= TAG_LEN
      ct  = raw[0, raw.bytesize - TAG_LEN]
      tag = raw[-TAG_LEN..]
      cipher = OpenSSL::Cipher.new(CIPHER)
      cipher.decrypt
      cipher.key      = spamtrap_crypto_key
      cipher.iv       = salt_bytes
      cipher.auth_tag = tag
      (cipher.update(ct) + cipher.final).to_sym
    rescue OpenSSL::Cipher::CipherError, ArgumentError
      nil
    end
  end
end
