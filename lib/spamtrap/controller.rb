module Spamtrap::Controller

  def self.included(base)
    base.extend ActsAsMethods
  end

  module ActsAsMethods
    def spamtrap(honeypot = 'spamtrap', options = {}, &block)
      nonce_enabled = options.delete(:nonce)
      nonce_timeout = options.delete(:nonce_timeout) || Spamtrap.nonce_timeout

      before_action(options) do |controller|
        controller.instance_eval(&block) if block_given?
        controller.instance_eval do
          if params[honeypot].present?
            Rails.logger.warn "Spamtrap triggered by #{request.remote_ip}."
            head 200
          elsif nonce_enabled && !spamtrap_valid_nonce?(nonce_timeout)
            Rails.logger.warn "Spamtrap nonce invalid from #{request.remote_ip}."
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

  private :spamtrap_valid_nonce?

end

ActionController::Base.send :include, Spamtrap::Controller
