require 'openssl'
require 'ipaddr'

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

    attr_writer :filter_parameters

    # Apply the app's filter_parameters to mutated field names in the log. Default true.
    def filter_parameters
      @filter_parameters.nil? ? true : @filter_parameters
    end

    attr_writer :nonce_bind_ip

    # true binds the nonce to the full client IP (default), :prefix to its /24 or /48
    # network (tolerates mobile handoff/CGNAT), false does not bind it to the IP at all.
    def nonce_bind_ip
      @nonce_bind_ip.nil? ? true : @nonce_bind_ip
    end

    attr_writer :min_fill_time

    # Minimum seconds between render and submission a human needs; false or 0 disables. Default 1.
    def min_fill_time
      @min_fill_time.nil? ? 1 : @min_fill_time
    end

    attr_writer :secret_key_base

    # The current HKDF source secret; defaults to the app's own so no setup is needed to opt in.
    def secret_key_base
      @secret_key_base || Rails.application.secret_key_base
    end

    attr_writer :honeypot_styles, :js_proof, :suspicious_if

    # Decoys f.spamtrap renders: any of :textarea, :text, :checkbox. Default is the textarea only.
    def honeypot_styles
      Array(@honeypot_styles.nil? ? :textarea : @honeypot_styles).map(&:to_sym)
    end

    # Require a hidden field that only an executing script fills in; excludes no-JS users.
    def js_proof
      @js_proof || false
    end

    # App-defined heuristic run after every other check; truthy result traps as :content.
    def suspicious_if
      @suspicious_if
    end

    attr_writer :previous_secret_key_base

    # Set during a rotation window so tokens minted under the old secret still verify/decrypt.
    def previous_secret_key_base
      @previous_secret_key_base
    end

    attr_writer :token_context

    # Callable taking the request and returning a String mixed into every token, so a token
    # minted on one hostname doesn't verify on another. Off (nil) by default.
    def token_context
      @token_context
    end
  end

  # nil when token_context is unset, so the token format is unchanged for apps that don't opt in.
  def self.token_context_for(request)
    token_context && token_context.call(request).to_s
  end

  # Normalises ip per mode: true keeps it as-is, :prefix masks to its /24 (IPv4) or /48 (IPv6)
  # network (IPv4-mapped addresses unmapped first so they mask as IPv4), false discards it.
  def self.normalize_ip(ip, mode = nonce_bind_ip)
    case mode
    when false
      ''
    when :prefix
      begin
        addr = IPAddr.new(ip.to_s)
        addr = addr.native if addr.ipv4_mapped?
        bits = addr.ipv4? ? 24 : 48
        "#{addr.mask(bits)}/#{bits}"
      rescue IPAddr::InvalidAddressError
        ip.to_s
      end
    else
      ip.to_s
    end
  end

  # Parameter names for each honeypot style, derived from the declared name so the view and
  # controller agree without extra configuration. With mutation on they are encrypted like any field.
  def self.honeypot_fields(name)
    { textarea: name.to_s, text: "#{name}_input", checkbox: "#{name}_check" }
  end

  # Key for Rack::Attack / Rails' rate_limit, scoped by the normalized client IP.
  def self.throttle_key(request)
    "spamtrap:#{normalize_ip(request.remote_ip)}"
  end

  # Wires the gem into Action Controller and Action View. The Railtie calls the two halves
  # from on_load hooks; outside a Rails app call install! after those frameworks are loaded.
  def self.install!
    install_controller!
    install_form_builder!
  end

  def self.install_controller!
    ActionController::Base.include Spamtrap::Controller unless ActionController::Base < Spamtrap::Controller
    # const_defined?(false) avoids autoloading action_controller/api.rb for apps that never use it.
    return unless ActionController.const_defined?(:API, false)

    ActionController::API.include Spamtrap::Controller unless ActionController::API < Spamtrap::Controller
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
  require 'spamtrap/parameter_filter'
  require 'spamtrap/railtie' if defined?(Rails::Railtie)
end
