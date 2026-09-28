require 'rails/generators'

module Spamtrap
  module Generators
    class InstallGenerator < Rails::Generators::Base
      source_root File.expand_path('templates', __dir__)

      desc 'Creates a Spamtrap initializer documenting every configuration option and its default.'

      def create_initializer
        template 'spamtrap.rb', 'config/initializers/spamtrap.rb'
      end
    end
  end
end
