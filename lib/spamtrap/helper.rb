class ActionView::Helpers::FormBuilder
  def spamtrap(parameter='spamtrap', options={})
    options.reverse_merge!({:class => 'spamtrap'})
    @template.text_area_tag(parameter, nil, options)
  end

  # # def nonce(method, tag_value, options = {})
  # def cryptographic_nonce(options = {})
  #   # @template.hidden_field(@object_name, method, tag_value, objectify_options(options))
  #   now, random = Time.now.to_i, SecureRandom.hex
  #   # OpenSSL::HMAC.hexdigest()
  #   cryptographic_nonce = Digest::MD5.hexdigest([timestamp, Rails.application.config.secret_key_base].join(':'))
  #   @template.hidden_field(@object_name, :timestamp, now, objectify_options(options)) +
  #   @template.hidden_field(@object_name, :random, random, objectify_options(options)) +
  #   @template.hidden_field(@object_name, :spinner, cryptographic_nonce(now), objectify_options(options))
  # end
end
