require 'base64'
require 'securerandom'
require 'ipaddr'

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

    # aad binds the token to the render timestamp so it can't be replayed under a different one.
    def spamtrap_encrypt_field(field_name, aad)
      cipher = OpenSSL::Cipher.new(CIPHER)
      cipher.encrypt
      cipher.key = spamtrap_crypto_key
      cipher.iv  = iv = SecureRandom.bytes(NONCE_LEN)
      cipher.auth_data = aad.to_s
      ct = cipher.update(field_name.to_s) + cipher.final
      Base64.urlsafe_encode64(iv + ct + cipher.auth_tag(TAG_LEN), padding: false)
    end

    def spamtrap_decrypt_field(token, aad)
      raw = Base64.urlsafe_decode64(token)
      return nil unless raw.bytesize > NONCE_LEN + TAG_LEN
      iv  = raw[0, NONCE_LEN]
      ct  = raw[NONCE_LEN...-TAG_LEN]
      tag = raw[-TAG_LEN..]
      cipher = OpenSSL::Cipher.new(CIPHER)
      cipher.decrypt
      cipher.key       = spamtrap_crypto_key
      cipher.iv        = iv
      cipher.auth_data = aad.to_s
      cipher.auth_tag  = tag
      (cipher.update(ct) + cipher.final).to_sym
    rescue OpenSSL::Cipher::CipherError, ArgumentError
      nil
    end

    def spamtrap_nonce_key
      @spamtrap_nonce_key ||= OpenSSL::KDF.hkdf(
        Rails.application.secret_key_base,
        salt:   'spamtrap-nonce',
        info:   '',
        length: 32,
        hash:   'SHA256'
      )
    end

    # v1: versions the message for future key rotation; honeypot scopes a token to one form.
    def spamtrap_nonce_digest(timestamp, ip, honeypot, nonce_id)
      OpenSSL::HMAC.hexdigest('SHA256', spamtrap_nonce_key, "v1:#{timestamp}:#{spamtrap_nonce_ip(ip)}:#{honeypot}:#{nonce_id}")
    end

    # Normalised here (not in helper.rb) so the view helper and controller agree on the
    # bound value without either one duplicating Spamtrap.nonce_bind_ip's semantics.
    def spamtrap_nonce_ip(ip)
      case Spamtrap.nonce_bind_ip
      when false
        ''
      when :prefix
        begin
          addr = IPAddr.new(ip.to_s)
          addr = addr.native if addr.ipv4_mapped? # ::ffff:1.2.3.4 must mask as IPv4, not collapse into one /48
          bits = addr.ipv4? ? 24 : 48
          "#{addr.mask(bits)}/#{bits}"
        rescue IPAddr::InvalidAddressError
          ip.to_s
        end
      else
        ip.to_s
      end
    end
  end
end
