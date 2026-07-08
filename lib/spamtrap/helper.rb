class ActionView::Helpers::FormBuilder
  def spamtrap(parameter = 'spamtrap', options = {})
    nonce = options.delete(:nonce)
    options.reverse_merge!(class: 'spamtrap')
    honeypot = @template.text_area_tag(parameter, nil, options)
    nonce ? honeypot + spamtrap_nonce_fields : honeypot
  end

  private

  def spamtrap_nonce_fields
    timestamp = Time.now.to_i
    ip = @template.request.remote_ip
    secret = Rails.application.secret_key_base
    nonce = OpenSSL::HMAC.hexdigest('SHA256', secret, "#{timestamp}:#{ip}")

    @template.hidden_field_tag(:spamtrap_timestamp, timestamp) +
      @template.hidden_field_tag(:spamtrap_nonce, nonce)
  end
end
