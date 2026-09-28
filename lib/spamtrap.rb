require 'openssl'

module Spamtrap
  class << self
    attr_accessor :on_trap
    attr_writer :stable_ids

    # Whether mutated fields keep an id/for derived from the real field name (e.g.
    # #message_name) instead of the opaque encrypted one. Default true.
    def stable_ids
      @stable_ids.nil? ? true : @stable_ids
    end

    attr_writer   :nonce, :nonce_timeout, :mutate, :mutation_timeout, :nonce_skew, :allowed_params

    def nonce
      @nonce || false
    end

    def nonce_timeout
      @nonce_timeout || 1800
    end

    # false, true (strict), :strict, or :lenient (remap only; never traps a plaintext key).
    def mutate
      @mutate || false
    end

    # Extra top-level param names a strict action accepts unencrypted (e.g. app-added form fields).
    def allowed_params
      Array(@allowed_params).map(&:to_s)
    end

    def mutation_timeout
      @mutation_timeout || nonce_timeout
    end

    # How far a token's timestamp may sit in the future (clock skew), before it's rejected.
    def nonce_skew
      @nonce_skew || 60
    end

    attr_writer :nonce_store

    # Where nonce: :single_use records seen nonce ids; defaults to the app's cache.
    def nonce_store
      @nonce_store || Rails.cache
    end

    attr_writer :trap_response

    # How a trapped request responds: :head, :no_content, :unprocessable, :redirect_back,
    # a callable, or a Hash keyed by trap reason. See Spamtrap::Controller#spamtrap_render_trap.
    def trap_response
      @trap_response || :head
    end

    attr_writer :enabled

    # Global kill switch; false skips every spamtrap check (honeypot, nonce, mutation).
    def enabled
      @enabled.nil? ? true : @enabled
    end

    attr_writer :nonce_bind_ip

    # true binds the nonce to the full client IP (default), :prefix to its /24 or /48
    # network (tolerates mobile handoff/CGNAT), false does not bind it to the IP at all.
    def nonce_bind_ip
      @nonce_bind_ip.nil? ? true : @nonce_bind_ip
    end
  end

  # Wires the gem into Action Controller and Action View. The Railtie calls the two halves
  # from on_load hooks; outside a Rails app call install! after those frameworks are loaded.
  def self.install!
    install_controller!
    install_form_builder!
  end

  def self.install_controller!
    ActionController::Base.include Spamtrap::Controller unless ActionController::Base < Spamtrap::Controller
  end

  def self.install_form_builder!
    builder = ActionView::Helpers::FormBuilder
    builder.prepend Spamtrap::FormBuilderMutation unless builder < Spamtrap::FormBuilderMutation
    builder.include Spamtrap::FormBuilderHelper   unless builder < Spamtrap::FormBuilderHelper
  end

  # True once action_view/helpers has loaded, checked without triggering the autoload
  # (defined?(ActionView::Helpers::FormBuilder) would load it).
  def self.form_builder_loaded?
    defined?(ActionView) && ActionView.autoload?(:Helpers).nil? &&
      ActionView.const_defined?(:Helpers, false) && ActionView::Helpers.const_defined?(:FormBuilder, false)
  end

  require 'spamtrap/crypto'
  require 'spamtrap/controller'
  require 'spamtrap/helper'
  require 'spamtrap/railtie' if defined?(Rails::Railtie)
end
