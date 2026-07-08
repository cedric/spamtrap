require 'rubygems'
require 'rails'
require 'action_controller'
require 'action_controller/test_case'
require 'minitest/autorun'
require 'spamtrap'

class SpamtrapTestApp < Rails::Application
  config.secret_key_base = 'a' * 64
  config.eager_load = false
  config.logger = Logger.new(nil)
end

Rails.application.initialize!

Rails.application.routes.draw do
  post 'honeypot/create',      to: 'honeypot#create'
  post 'nonce/create',         to: 'nonce#create'
  post 'nonce_timeout/create', to: 'nonce_timeout#create'
  post 'mutation/create',      to: 'mutation#create'
  post 'nested_mutation/create', to: 'nested_mutation#create'
end

class ActionController::TestCase
  setup do
    @routes = Rails.application.routes
  end
end
