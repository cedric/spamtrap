# frozen_string_literal: true

module Spamtrap
  # Raised by spamtrap_nonce_fields when there's no request to bind the nonce to
  # (mailers, ApplicationController.render outside a request, etc.).
  class NoRequestError < StandardError; end

  module FormBuilderMutation
    include Spamtrap::Crypto

    MUTABLE_FIELDS = %i[
      text_field email_field password_field number_field url_field telephone_field
      text_area check_box hidden_field file_field date_field time_field
      datetime_local_field month_field week_field search_field color_field
      range_field select collection_select grouped_collection_select label
      radio_button phone_field datetime_field time_zone_select weekday_select
      collection_check_boxes collection_radio_buttons date_select time_select
      datetime_select rich_text_area
    ].freeze

    MUTABLE_FIELDS.each do |m|
      define_method(m) do |field, *args, &blk|
        if @spamtrap_timestamp
          encrypted_field = spamtrap_token_for(field)

          opts =
            if m == :check_box
              args.first.is_a?(Hash) ? args.shift.dup : {}
            else
              args.last.is_a?(Hash) ? args.pop.dup : {}
            end

          model_value = object.respond_to?(field) ? object.public_send(field) : nil

          html =
            case m
            when :check_box
              spamtrap_apply_model_value(m, opts, model_value)
              opts[:id] = field_id(field) if Spamtrap.stable_ids && !opts.key?(:id)
              super(encrypted_field, opts, *args, &blk)
            when :radio_button
              tag_value = args.first
              spamtrap_apply_model_value(m, opts, model_value, tag_value)
              opts[:id] = spamtrap_radio_id(field, tag_value) if Spamtrap.stable_ids && !opts.key?(:id)
              super(encrypted_field, *args, opts, &blk)
            when :select, :collection_select, :grouped_collection_select, :weekday_select
              # :selected belongs in the inner options hash, not html_options (the last hash).
              # After popping html_options into opts, args.last is the options hash (if present).
              if args.last.is_a?(Hash)
                sel_opts = args.pop.dup
                spamtrap_apply_model_value(m, sel_opts, model_value)
                args.push(sel_opts)
              else
                spamtrap_apply_model_value(m, opts, model_value)
              end
              opts[:id] = field_id(field) if Spamtrap.stable_ids && !opts.key?(:id)
              super(encrypted_field, *args, opts, &blk)
            when :time_zone_select
              # Unlike the others above, priority_zones sits before options; pad it back in
              # when the caller omitted it entirely so opts lands as options, not priority_zones.
              if args.last.is_a?(Hash)
                sel_opts = args.pop.dup
                spamtrap_apply_model_value(m, sel_opts, model_value)
                args.push(sel_opts)
              else
                args.push(nil) if args.empty?
                spamtrap_apply_model_value(m, opts, model_value)
              end
              opts[:id] = field_id(field) if Spamtrap.stable_ids && !opts.key?(:id)
              super(encrypted_field, *args, opts, &blk)
            when :collection_check_boxes, :collection_radio_buttons
              # Rails computes each collection item's own <input> id internally; left opaque.
              if args.last.is_a?(Hash)
                sel_opts = args.pop.dup
                spamtrap_apply_model_value(m, sel_opts, model_value)
                args.push(sel_opts)
              else
                spamtrap_apply_model_value(m, opts, model_value)
              end
              super(encrypted_field, *args, opts, &blk)
            when :date_select, :time_select, :datetime_select
              # Rails derives each <select>'s id from its multiparameter suffix (e.g. "(1i)"); left opaque.
              if args.last.is_a?(Hash)
                sel_opts = args.pop.dup
                spamtrap_apply_model_value(m, sel_opts, model_value)
                args.push(sel_opts)
              else
                spamtrap_apply_model_value(m, opts, model_value)
              end
              super(encrypted_field, *args, opts, &blk)
            when :label
              # Preserve the human-readable label text using the real field name
              # before substituting the encrypted form. Mirrors Rails' own
              # resolution order:
              #   1. explicit text argument — kept as-is
              #   2. activerecord.attributes.Model.field (ActiveRecord models)
              #   3. helpers.label.object_name.field (plain objects / form_with)
              #   4. humanize fallback
              # Discard any explicit nil that a subclass may have passed through
              # (e.g. `super(method, nil, options)`) so it does not survive as a
              # spurious positional argument in the final super call.
              args.compact!
              unless args.first.is_a?(String)
                human_text =
                  if object.respond_to?(:to_model)
                    object.class.human_attribute_name(field.to_s, default: field.to_s.humanize)
                  else
                    I18n.t(field, scope: [:helpers, :label, object_name], default: field.to_s.humanize)
                  end
                args.unshift(human_text)
              end
              opts[:for] = field_id(field) if Spamtrap.stable_ids && !opts.key?(:for)
              super(encrypted_field, *args, opts, &blk)
            when :rich_text_area
              # Action Text may not be loaded, so FormBuilder won't define this method at all;
              # `super` would then raise a confusing "super: no superclass method" instead of
              # a normal NoMethodError naming the method the caller actually tried to call.
              spamtrap_apply_model_value(m, opts, model_value)
              if defined?(super)
                super(encrypted_field, *args, opts, &blk)
              else
                raise NoMethodError, "undefined method `#{m}' for an instance of #{self.class}"
              end
            else
              spamtrap_apply_model_value(m, opts, model_value)
              opts[:id] = field_id(field) if Spamtrap.stable_ids && !opts.key?(:id)
              super(encrypted_field, *args, opts, &blk)
            end

          spamtrap_error_wrap(html, field)
        else
          super(field, *args, &blk)
        end
      end
    end

    def initialize(object_name, object, template, options)
      super
      @spamtrap_options = options[:spamtrap] if options[:spamtrap].is_a?(Hash)
      @spamtrap_timestamp = options[:spamtrap_timestamp] if options[:spamtrap_timestamp]
      @spamtrap_tokens    = options[:spamtrap_tokens]    if options[:spamtrap_tokens]
      # Mint the shared timestamp up front so mutation works no matter where f.spamtrap
      # is called in the form (or if it's never called at all).
      @spamtrap_timestamp ||= Time.now.to_i if @spamtrap_options && @spamtrap_options[:mutate]
    end

    def fields_for(record_name, record_object = nil, fields_options = {}, &block)
      if @spamtrap_timestamp
        # Children share the parent's token cache: indexless `items[][name]` arrays only split
        # into separate records when the same field name repeats as the same key.
        shared = { spamtrap_timestamp: @spamtrap_timestamp, spamtrap_tokens: (@spamtrap_tokens ||= {}) }
        if record_object.is_a?(Hash) && record_object.extractable_options?
          record_object = record_object.merge(shared)
        else
          fields_options = fields_options.merge(shared)
        end
      end
      super(record_name, record_object, fields_options, &block)
    end

    private

    # One token per field name per render (shared with fields_for children), or a fresh IV per
    # call would make <label for> and <input id> mismatch and split indexless array records.
    def spamtrap_token_for(field)
      @spamtrap_tokens ||= {}
      @spamtrap_tokens[field.to_s] ||= spamtrap_encrypt_field(field.to_s, @spamtrap_timestamp)
    end

    # Fills in the key each helper reads its pre-filled state from (:value, :checked,
    # :selected...), unless the caller already gave one explicitly.
    def spamtrap_apply_model_value(m, target, model_value, tag_value = nil)
      # Some tags (Rails 8.1 date/time fields, time_zone_select, weekday_select) read the
      # model value eagerly via the encrypted method name; this tells Rails to return nil
      # instead of raising. Rails deletes the key, so it never reaches the HTML.
      target[:allow_method_names_outside_object] = true unless target.key?(:allow_method_names_outside_object)

      case m
      when :check_box
        target[:checked] = !!model_value unless target.key?(:checked)
      when :radio_button
        target[:checked] = (model_value.to_s == tag_value.to_s) unless target.key?(:checked)
      when :select, :collection_select, :grouped_collection_select, :weekday_select
        target[:selected] = model_value unless target.key?(:selected)
      when :time_zone_select
        # Unlike the others, TimeZoneSelect falls back to :default, not :selected.
        target[:default] = model_value unless target.key?(:default)
      when :collection_check_boxes, :collection_radio_buttons
        target[:checked] = model_value unless target.key?(:checked)
      when :date_select, :time_select, :datetime_select
        target[:selected] = model_value unless target.key?(:selected) || target.key?(:default) || model_value.nil?
      else
        target[:value] = model_value unless target.key?(:value)
      end
    end

    # Mirrors ActionView::Helpers::Tags::Base#sanitized_value so a radio button's id is
    # identical to what an unmutated render would produce, just rooted at the real field name.
    def spamtrap_radio_id(field, tag_value)
      suffix = tag_value.to_s.gsub(/[\s.]/, '_').gsub(/[^-[[:word:]]]/, '').downcase
      field_id(field, suffix)
    end

    # Rails looks up object.errors[method] using the (encrypted) method name it was given,
    # which never has errors for a mutated field, so field_with_errors silently stops
    # applying. Replicate it here using the real field name instead.
    def spamtrap_error_wrap(html, field)
      return html unless object.respond_to?(:errors) && object.errors[field].present?

      tag_stub = Struct.new(:object, :method_name, :error_message).new(object, field.to_s, object.errors[field])
      @template.instance_exec(html, tag_stub, &ActionView::Base.field_error_proc)
    end
  end
end

# The f.spamtrap helper. Mixed into ActionView::Helpers::FormBuilder by Spamtrap.install!
# (via the Railtie in a Rails app) rather than by reopening the class at require time.
module Spamtrap::FormBuilderHelper
  def spamtrap(parameter = 'spamtrap', options = {})
    mutate  = options.key?(:mutate)         ? options.delete(:mutate)         : spamtrap_option_default(:mutate)
    nonce   = options.key?(:nonce)          ? options.delete(:nonce)          : spamtrap_option_default(:nonce)
    bind_ip = options.key?(:nonce_bind_ip)  ? options.delete(:nonce_bind_ip)  : spamtrap_option_default(:nonce_bind_ip)
    options.reverse_merge!(class: 'spamtrap', tabindex: -1, autocomplete: 'off', 'aria-hidden' => true, style: 'display:none')

    # One timestamp per render, shared by mutation tokens and the nonce HMAC, so the hidden
    # field is emitted once whether one or both features are on. Reuse the timestamp already
    # minted at builder construction (spamtrap: { mutate: true }) instead of a fresh one.
    timestamp = @spamtrap_timestamp || (Time.now.to_i if mutate || nonce)
    @spamtrap_timestamp = timestamp if mutate

    # Mutate the honeypot's own name too, or its static name is the one field a bot can
    # learn to skip; id stays opaque (no stable_ids) since a stable honeypot id would out it.
    honeypot_field = @spamtrap_timestamp ? spamtrap_token_for(parameter.to_s) : parameter

    @template.text_area_tag(honeypot_field, nil, options) +
      ((mutate || nonce) ? @template.hidden_field_tag(:spamtrap_timestamp, timestamp) : ''.html_safe) +
      (nonce ? spamtrap_nonce_fields(timestamp, parameter.to_s, bind_ip) : ''.html_safe)
  end

  private

  def spamtrap_option_default(key)
    if @spamtrap_options&.key?(key)
      @spamtrap_options[key]
    else
      Spamtrap.public_send(key)
    end
  end

  def spamtrap_nonce_fields(timestamp, honeypot, bind_ip)
    unless @template.respond_to?(:request) && @template.request
      raise Spamtrap::NoRequestError, 'Spamtrap nonce fields need a request; render the form inside a request or pass nonce: false'
    end

    ip       = @template.request.remote_ip
    nonce_id = SecureRandom.hex(16)
    nonce    = spamtrap_nonce_digest(timestamp, ip, honeypot, nonce_id, bind_ip: bind_ip)

    @template.hidden_field_tag(:spamtrap_nonce_id, nonce_id) +
      @template.hidden_field_tag(:spamtrap_nonce, nonce)
  end
end
