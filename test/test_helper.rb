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
  post 'nested_mutation/create',  to: 'nested_mutation#create'
  post 'global_defaults/create',  to: 'global_defaults#create'
  post 'global_override/create',  to: 'global_override#create'
  post 'on_trap_global_callback/create',       to: 'on_trap_global_callback#create'
  post 'on_trap_global_nonce_callback/create', to: 'on_trap_global_nonce_callback#create'
  post 'on_trap_per_declaration/create',       to: 'on_trap_per_declaration#create'
end

class ActionController::TestCase
  setup do
    @routes = Rails.application.routes
  end
end
