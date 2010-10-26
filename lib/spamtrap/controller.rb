module Spamtrap
  
  def self.included(base)
    base.extend ActsAsMethods
  end
  
  module ActsAsMethods
    def spamtrap(actions, parameter='spamtrap')
      actions = [actions] unless actions.is_a?(Array)
      raise 'Spamtrap must have actions defined.' if actions.empty?
      before_filter(:only => actions) do |controller|
        controller.instance_eval do
          if params[parameter.to_s].present?
            Rails.logger.warn "Spamtrap triggered by #{request.remote_ip}."
            render :nothing => true, :status => 200
          end
        end
      end
    end
  end
  
end

ActionController::Base.send :include, Spamtrap
