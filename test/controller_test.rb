require File.join(File.dirname(__FILE__), 'test_helper')

# Test controllers — render a body so we can distinguish a real response
# from a spamtrap-blocked one (which uses head 200 and has an empty body).

class HoneypotController < ActionController::Base
  spamtrap :trap_field, only: :create

  def create
    render plain: 'success'
  end
end

class NonceController < ActionController::Base
  spamtrap :trap_field, nonce: true, only: :create

  def create
    render plain: 'success'
  end
end

class NonceTimeoutController < ActionController::Base
  spamtrap :trap_field, nonce: true, nonce_timeout: 60, only: :create

  def create
    render plain: 'success'
  end
end

module NonceTestHelper
  REMOTE_IP = '0.0.0.0'

  def generate_nonce(timestamp, ip = REMOTE_IP)
    secret = Rails.application.secret_key_base
    OpenSSL::HMAC.hexdigest('SHA256', secret, "#{timestamp}:#{ip}")
  end
end

class HoneypotControllerTest < ActionController::TestCase
  tests HoneypotController

  def test_empty_honeypot_allows_request
    post :create, params: { trap_field: '' }
    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_filled_honeypot_silently_discards
    post :create, params: { trap_field: 'buy cheap meds' }
    assert_response :ok
    assert_empty response.body
  end
end

class NonceControllerTest < ActionController::TestCase
  include NonceTestHelper
  tests NonceController

  def test_valid_nonce_allows_request
    timestamp = Time.now.to_i
    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      spamtrap_nonce: generate_nonce(timestamp)
    }
    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_tampered_nonce_is_rejected
    timestamp = Time.now.to_i
    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      spamtrap_nonce: 'deadbeef'
    }
    assert_response :ok
    assert_empty response.body
  end

  def test_expired_nonce_is_rejected
    timestamp = Time.now.to_i - 7200
    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      spamtrap_nonce: generate_nonce(timestamp)
    }
    assert_response :ok
    assert_empty response.body
  end

  def test_missing_nonce_fields_are_rejected
    post :create, params: { trap_field: '' }
    assert_response :ok
    assert_empty response.body
  end

  def test_filled_honeypot_takes_priority_over_valid_nonce
    timestamp = Time.now.to_i
    post :create, params: {
      trap_field: 'spam',
      spamtrap_timestamp: timestamp,
      spamtrap_nonce: generate_nonce(timestamp)
    }
    assert_response :ok
    assert_empty response.body
  end
end

class NonceTimeoutControllerTest < ActionController::TestCase
  include NonceTestHelper
  tests NonceTimeoutController

  def test_nonce_within_custom_timeout_passes
    timestamp = Time.now.to_i - 30
    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      spamtrap_nonce: generate_nonce(timestamp)
    }
    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_nonce_beyond_custom_timeout_is_rejected
    timestamp = Time.now.to_i - 120
    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      spamtrap_nonce: generate_nonce(timestamp)
    }
    assert_response :ok
    assert_empty response.body
  end
end
