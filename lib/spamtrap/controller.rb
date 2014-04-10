module Spamtrap::Controller

  def self.included(base)
    base.extend ActsAsMethods
  end

  module ActsAsMethods
    def spamtrap(honeypot = 'spamtrap', options = {}, &block)
      before_filter(options) do |controller|
        controller.instance_eval(&block) if block_given?
        controller.instance_eval do
          if params[honeypot].present?
            Rails.logger.warn "Spamtrap triggered by #{request.remote_ip}."
            render :nothing => true, :status => 200
          end
        end
      end
    end
  end

end

ActionController::Base.send :include, Spamtrap::Controller
