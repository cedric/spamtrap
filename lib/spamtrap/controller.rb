module Spamtrap
  
  def self.included(base)
    base.extend ActsAsMethods
  end
  
  module ActsAsMethods
    def spamtrap(actions, parameter='spamtrap')
      raise 'Spamtrap must have actions defined.' if actions.empty?
      # helper_attr :spamtrap_parameter
      # attr_accessor :spamtrap_parameter
      # self.spamtrap_parameter = parameter
      before_filter(:only => actions.is_a?(Array) ? actions : [actions]) do |controller|
        controller.instance_eval do
          if params[parameter.to_s].present?
            render :nothing => true, :status => 200
          end
        end
      end
    end
  end
  
end

ActionController::Base.send :include, Spamtrap
