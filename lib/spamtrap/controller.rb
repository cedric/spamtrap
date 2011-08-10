module Spamtrap::Controller
  
  def self.included(base)
    base.extend ActsAsMethods
  end
  
  module ActsAsMethods
    def spamtrap(actions, honeypot='spamtrap', &block)
      actions = [actions] unless actions.is_a?(Array)
      raise 'Spamtrap must have actions defined.' if actions.empty?
      before_filter(:only => actions) do |controller|
        if block_given?
          controller.instance_eval(&block)
        end
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
