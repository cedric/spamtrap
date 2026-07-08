module Spamtrap::Controller
  include Spamtrap::Crypto

  def self.included(base)
    base.extend ActsAsMethods
  end

  module ActsAsMethods
    def spamtrap(honeypot = 'spamtrap', options = {}, &block)
      # Capture explicit per-call values; use sentinel so globals are read
      # at request time rather than at class definition time.
      nonce_opt    = options.key?(:nonce)         ? options.delete(:nonce)         : :global
      timeout_opt  = options.key?(:nonce_timeout) ? options.delete(:nonce_timeout) : :global
      mutate_opt   = options.key?(:mutate)        ? options.delete(:mutate)        : :global
      on_trap_opt  = options.key?(:on_trap)       ? options.delete(:on_trap)       : :global

      before_action(options) do |controller|
        controller.instance_eval(&block) if block_given?
        controller.instance_eval do
          nonce_enabled  = nonce_opt   == :global ? Spamtrap.nonce         : nonce_opt
          nonce_timeout  = timeout_opt == :global ? Spamtrap.nonce_timeout : timeout_opt
          mutate_enabled = mutate_opt  == :global ? Spamtrap.mutate        : mutate_opt

          spamtrap_remap_params if mutate_enabled

          if params[honeypot].present?
            Rails.logger.warn "Spamtrap triggered by #{request.remote_ip}."
            spamtrap_invoke_on_trap(:honeypot, on_trap_opt)
            head 200
          elsif nonce_enabled && !spamtrap_valid_nonce?(nonce_timeout)
            Rails.logger.warn "Spamtrap nonce invalid from #{request.remote_ip}."
            spamtrap_invoke_on_trap(:nonce, on_trap_opt)
            head 200
          end
        end
      end
    end
  end

  def spamtrap_valid_nonce?(timeout)
    timestamp = params[:spamtrap_timestamp].to_i
    nonce = params[:spamtrap_nonce].to_s
    return false if timestamp.zero? || nonce.empty?
    return false if Time.now.to_i - timestamp > timeout.to_i

    secret = Rails.application.secret_key_base
    expected = OpenSSL::HMAC.hexdigest('SHA256', secret, "#{timestamp}:#{request.remote_ip}")
    ActiveSupport::SecurityUtils.secure_compare(nonce, expected)
  end

  def spamtrap_remap_params
    salt_hex = params[:spamtrap_mutation_salt].to_s
    return if salt_hex.empty?

    salt_bytes = [salt_hex].pack('H*')
    return unless salt_bytes.bytesize == Spamtrap::Crypto::NONCE_LEN

    spamtrap_remap_hash(params, salt_bytes)
  rescue ArgumentError
    nil
  end

  def spamtrap_remap_hash(hash, salt)
    hash.each_key.to_a.each do |key|
      real = spamtrap_decrypt_field(key.to_s, salt)
      if real
        hash[real] = hash.delete(key)
        key = real
      end
      child = hash[key]
      spamtrap_remap_hash(child, salt) if child.is_a?(ActionController::Parameters)
    end
  end

  def spamtrap_invoke_on_trap(reason, on_trap_opt)
    callback = on_trap_opt == :global ? Spamtrap.on_trap : on_trap_opt
    return unless callback.respond_to?(:call)
    callback.call(reason: reason, request: request)
  rescue StandardError => e
    Rails.logger.error "Spamtrap on_trap callback raised: #{e.class}: #{e.message}"
  end

  private :spamtrap_valid_nonce?, :spamtrap_remap_params, :spamtrap_remap_hash, :spamtrap_invoke_on_trap

end

ActionController::Base.send :include, Spamtrap::Controller
