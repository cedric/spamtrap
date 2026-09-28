ENV['RAILS_ENV'] ||= 'test' # integration tests go through the middleware stack, which blocks unknown hosts in development
require 'rubygems'
require 'rails'
require 'action_controller'
require 'action_controller/test_case'
require 'action_view'
require 'action_view/test_case'
require 'minitest/autorun'
require 'spamtrap'
require 'spamtrap/test_helper'

class SpamtrapTestApp < Rails::Application
  config.secret_key_base = 'a' * 64
  config.eager_load = false
  config.logger = Logger.new(nil)
  config.cache_store = :memory_store # a bare app defaults to a file store under tmp/
end

Rails.application.initialize!

# Existing tests mint timestamps as Time.now.to_i; disable by default so they don't all become :too_fast.
Spamtrap.min_fill_time = false

Rails.application.routes.draw do
  get  'integration/new',    to: 'integration#new'
  get  'integration_js/new',    to: 'integration_js#new'
  post 'integration_js/create', to: 'integration_js#create'
  post 'js_proof_only/create',  to: 'js_proof_only#create'
  post 'strict_js_proof/create', to: 'strict_js_proof#create'
  post 'integration/create', to: 'integration#create'
  post 'honeypot/create',      to: 'honeypot#create'
  post 'nonce/create',         to: 'nonce#create'
  post 'nonce_timeout/create', to: 'nonce_timeout#create'
  post 'single_use_nonce/create', to: 'single_use_nonce#create'
  post 'mutation/create',      to: 'mutation#create'
  post 'strict_mutation/create', to: 'strict_mutation#create'
  post 'nested_mutation/create',  to: 'nested_mutation#create'
  post 'global_defaults/create',  to: 'global_defaults#create'
  post 'global_override/create',  to: 'global_override#create'
  post 'on_trap_global_callback/create',       to: 'on_trap_global_callback#create'
  post 'on_trap_global_nonce_callback/create', to: 'on_trap_global_nonce_callback#create'
  post 'on_trap_per_declaration/create',       to: 'on_trap_per_declaration#create'
  post 'mutation_echo/create',                 to: 'mutation_echo#create'
  post 'strict_mutation_echo/create',          to: 'strict_mutation_echo#create'
  post 'trap_response_unprocessable/create',   to: 'trap_response_unprocessable#create'
  post 'trap_response_global/create',          to: 'trap_response_global#create'
  post 'trap_response_override/create',        to: 'trap_response_override#create'
  post 'trap_response_hash_nonce/create',      to: 'trap_response_hash_nonce#create'
  post 'trap_response_callable/create',        to: 'trap_response_callable#create'
  post 'trap_response_redirect_back/create',   to: 'trap_response_redirect_back#create'
  post 'trap_response_on_trap_redirect/create', to: 'trap_response_on_trap_redirect#create'
  post 'trap_response_on_trap_payload/create',  to: 'trap_response_on_trap_payload#create'
  post 'trap_response_bogus/create',           to: 'trap_response_bogus#create'
  post 'strict_by_default/create',             to: 'strict_by_default#create'
  post 'strict_mutation_nonce/create',         to: 'strict_mutation_nonce#create'
  post 'mutation_expired_trap_response/create', to: 'mutation_expired_trap_response#create'
  post 'mutation_expired_on_trap/create',      to: 'mutation_expired_on_trap#create'
  post 'fill_time/create',                     to: 'fill_time#create'
  post 'fill_time_disabled/create',            to: 'fill_time_disabled#create'
  post 'fill_time_global/create',              to: 'fill_time_global#create'
  post 'nonce_bind_ip_action/create',          to: 'nonce_bind_ip_action#create'
  post 'api_honeypot/create',                  to: 'api_honeypot#create'
  post 'js_proof/create',                      to: 'js_proof#create'
  post 'content_hook/create',                  to: 'content_hook#create'
  post 'content_hook_keyword/create',          to: 'content_hook_keyword#create'
  post 'content_hook_raising/create',          to: 'content_hook_raising#create'
  post 'content_hook_not_called/create',       to: 'content_hook_not_called#create'
end

class ActionController::TestCase
  include Spamtrap::TestHelper

  setup do
    @routes = Rails.application.routes
  end
end

class ActionView::TestCase
  include Spamtrap::TestHelper
end
