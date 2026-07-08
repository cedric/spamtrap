module Spamtrap
  module FormBuilderMutation
    include Spamtrap::Crypto

    MUTABLE_FIELDS = %i[
      text_field email_field password_field number_field url_field telephone_field
      text_area check_box hidden_field file_field date_field time_field
      datetime_local_field month_field week_field search_field color_field
      range_field select collection_select grouped_collection_select label
    ].freeze

    MUTABLE_FIELDS.each do |m|
      define_method(m) do |field, *args, &blk|
        field = spamtrap_encrypt_field(field.to_s, @spamtrap_salt) if @spamtrap_salt
        super(field, *args, &blk)
      end
    end

    def initialize(object_name, object, template, options)
      super
      @spamtrap_salt = options[:spamtrap_salt] if options[:spamtrap_salt]
    end

    def fields_for(record_name, record_object = nil, fields_options = {}, &block)
      if @spamtrap_salt
        if record_object.is_a?(Hash) && record_object.extractable_options?
          record_object = record_object.merge(spamtrap_salt: @spamtrap_salt)
        else
          fields_options = fields_options.merge(spamtrap_salt: @spamtrap_salt)
        end
      end
      super(record_name, record_object, fields_options, &block)
    end
  end
end

class ActionView::Helpers::FormBuilder
  prepend Spamtrap::FormBuilderMutation

  def spamtrap(parameter = 'spamtrap', options = {})
    mutate = options.delete(:mutate)
    nonce  = options.delete(:nonce)
    options.reverse_merge!(class: 'spamtrap')

    if mutate
      @spamtrap_salt = SecureRandom.bytes(Spamtrap::Crypto::NONCE_LEN)
      salt_field = @template.hidden_field_tag(
        :spamtrap_mutation_salt, @spamtrap_salt.unpack1('H*')
      )
    end

    @template.text_area_tag(parameter, nil, options) +
      (nonce ? spamtrap_nonce_fields : ''.html_safe) +
      (salt_field || ''.html_safe)
  end

  private

  def spamtrap_nonce_fields
    timestamp = Time.now.to_i
    ip        = @template.request.remote_ip
    secret    = Rails.application.secret_key_base
    nonce     = OpenSSL::HMAC.hexdigest('SHA256', secret, "#{timestamp}:#{ip}")

    @template.hidden_field_tag(:spamtrap_timestamp, timestamp) +
      @template.hidden_field_tag(:spamtrap_nonce, nonce)
  end
end
