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

class MutationController < ActionController::Base
  spamtrap :trap_field, mutate: true, only: :create

  def create
    # Render the remapped comment param keys so tests can assert on them
    render plain: params[:comment].to_unsafe_h.keys.sort.join(',')
  end
end

class NestedMutationController < ActionController::Base
  spamtrap :trap_field, mutate: true, only: :create

  def create
    # Render top-level and nested address keys to verify salt propagation
    comment_keys = params[:comment].to_unsafe_h.except('address').keys.sort
    address_keys = params.dig(:comment, :address).to_unsafe_h.keys.sort rescue []
    render plain: "#{comment_keys.join(',')};#{address_keys.join(',')}"
  end
end

module NonceTestHelper
  REMOTE_IP = '0.0.0.0'

  def generate_nonce(timestamp, ip = REMOTE_IP)
    secret = Rails.application.secret_key_base
    OpenSSL::HMAC.hexdigest('SHA256', secret, "#{timestamp}:#{ip}")
  end
end

module MutationTestHelper
  include Spamtrap::Crypto

  MUTATION_SALT     = SecureRandom.bytes(Spamtrap::Crypto::NONCE_LEN)
  MUTATION_SALT_HEX = MUTATION_SALT.unpack1('H*')
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

class MutationControllerTest < ActionController::TestCase
  include MutationTestHelper
  tests MutationController

  def test_encrypted_field_names_are_remapped_to_real_names
    body_token  = spamtrap_encrypt_field('body',  MUTATION_SALT)
    email_token = spamtrap_encrypt_field('email', MUTATION_SALT)

    post :create, params: {
      trap_field: '',
      spamtrap_mutation_salt: MUTATION_SALT_HEX,
      comment: { body_token => 'Hello world', email_token => 'test@example.com' }
    }

    assert_response :ok
    assert_equal 'body,email', response.body
  end

  def test_unencrypted_field_names_pass_through_unchanged
    post :create, params: {
      trap_field: '',
      spamtrap_mutation_salt: MUTATION_SALT_HEX,
      comment: { body: 'Hello', email: 'test@example.com' }
    }

    assert_response :ok
    assert_equal 'body,email', response.body
  end

  def test_no_salt_leaves_encrypted_params_unmapped
    body_token = spamtrap_encrypt_field('body', MUTATION_SALT)

    post :create, params: {
      trap_field: '',
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    refute_equal 'body', response.body
  end

  def test_wrong_salt_fails_to_decrypt
    other_salt     = SecureRandom.bytes(Spamtrap::Crypto::NONCE_LEN)
    body_token     = spamtrap_encrypt_field('body', other_salt)

    post :create, params: {
      trap_field: '',
      spamtrap_mutation_salt: MUTATION_SALT_HEX,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    refute_equal 'body', response.body
  end
end

class NestedMutationControllerTest < ActionController::TestCase
  include MutationTestHelper
  tests NestedMutationController

  def test_salt_propagates_to_fields_for_child_builder
    body_token    = spamtrap_encrypt_field('body',    MUTATION_SALT)
    street_token  = spamtrap_encrypt_field('street',  MUTATION_SALT)
    city_token    = spamtrap_encrypt_field('city',    MUTATION_SALT)

    post :create, params: {
      trap_field: '',
      spamtrap_mutation_salt: MUTATION_SALT_HEX,
      comment: {
        body_token => 'Hello',
        address: {
          street_token => '123 Main St',
          city_token   => 'Springfield'
        }
      }
    }

    assert_response :ok
    assert_equal 'body;city,street', response.body
  end
end

# Controller that relies entirely on global defaults (no per-call options).
class GlobalDefaultsController < ActionController::Base
  spamtrap :trap_field, only: :create

  def create
    render plain: params[:comment].to_unsafe_h.keys.sort.join(',')
  end
end

# Controller that explicitly overrides global defaults with false.
class GlobalOverrideController < ActionController::Base
  spamtrap :trap_field, nonce: false, mutate: false, only: :create

  def create
    render plain: params[:comment].to_unsafe_h.keys.sort.join(',')
  end
end

class GlobalDefaultsControllerTest < ActionController::TestCase
  include MutationTestHelper
  include NonceTestHelper
  tests GlobalDefaultsController

  setup do
    Spamtrap.nonce  = true
    Spamtrap.mutate = true
  end

  teardown do
    Spamtrap.nonce  = false
    Spamtrap.mutate = false
  end

  def test_global_nonce_default_rejects_missing_nonce
    post :create, params: { trap_field: '', comment: { body: 'Hello' } }
    assert_response :ok
    assert_empty response.body
  end

  def test_global_nonce_default_accepts_valid_nonce
    timestamp = Time.now.to_i
    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      spamtrap_nonce: generate_nonce(timestamp),
      spamtrap_mutation_salt: MUTATION_SALT_HEX,
      comment: { spamtrap_encrypt_field('body', MUTATION_SALT) => 'Hello' }
    }
    assert_response :ok
    assert_equal 'body', response.body
  end

  def test_global_mutate_default_remaps_encrypted_fields
    body_token = spamtrap_encrypt_field('body', MUTATION_SALT)
    timestamp  = Time.now.to_i
    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      spamtrap_nonce: generate_nonce(timestamp),
      spamtrap_mutation_salt: MUTATION_SALT_HEX,
      comment: { body_token => 'Hello' }
    }
    assert_response :ok
    assert_equal 'body', response.body
  end
end

class GlobalOverrideControllerTest < ActionController::TestCase
  include MutationTestHelper
  tests GlobalOverrideController

  setup do
    Spamtrap.nonce  = true
    Spamtrap.mutate = true
  end

  teardown do
    Spamtrap.nonce  = false
    Spamtrap.mutate = false
  end

  def test_per_call_false_overrides_global_nonce
    # No nonce params — would fail if global nonce: true were in effect
    post :create, params: {
      trap_field: '',
      comment: { body: 'Hello' }
    }
    assert_response :ok
    assert_equal 'body', response.body
  end

  def test_per_call_false_overrides_global_mutate
    # Plain field name — would be remapped if global mutate: true were in effect
    post :create, params: {
      trap_field: '',
      spamtrap_mutation_salt: MUTATION_SALT_HEX,
      comment: { body: 'Hello' }
    }
    assert_response :ok
    assert_equal 'body', response.body
  end
end

# Controllers for on_trap callback tests.
class OnTrapGlobalCallbackController < ActionController::Base
  spamtrap :trap_field, only: :create

  def create
    render plain: 'success'
  end
end

class OnTrapGlobalNonceCallbackController < ActionController::Base
  spamtrap :trap_field, nonce: true, only: :create

  def create
    render plain: 'success'
  end
end

class OnTrapPerDeclarationController < ActionController::Base
  spamtrap :trap_field, only: :create,
    on_trap: ->(reason:, request:) { $per_decl_calls << { reason: reason, ip: request.remote_ip } }

  def create
    render plain: 'success'
  end
end

class OnTrapCallbackTest < ActionController::TestCase
  tests OnTrapGlobalCallbackController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << { reason: reason, ip: request.remote_ip } }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_global_callback_invoked_on_honeypot_trap
    post :create, params: { trap_field: 'spam' }
    assert_response :ok
    assert_empty response.body
    assert_equal 1, @calls.size
    assert_equal :honeypot, @calls.first[:reason]
  end

  def test_global_callback_not_invoked_on_legitimate_request
    post :create, params: { trap_field: '' }
    assert_response :ok
    assert_equal 'success', response.body
    assert_empty @calls
  end

  def test_no_callback_when_on_trap_is_nil
    Spamtrap.on_trap = nil
    post :create, params: { trap_field: 'spam' }
    assert_response :ok
    assert_empty response.body
    # no error raised — test simply passes
  end
end

class OnTrapNonceCallbackTest < ActionController::TestCase
  include NonceTestHelper
  tests OnTrapGlobalNonceCallbackController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << { reason: reason, ip: request.remote_ip } }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_global_callback_invoked_on_nonce_trap
    post :create, params: { trap_field: '' }
    assert_response :ok
    assert_empty response.body
    assert_equal 1, @calls.size
    assert_equal :nonce, @calls.first[:reason]
  end
end

class OnTrapPerDeclarationCallbackTest < ActionController::TestCase
  tests OnTrapPerDeclarationController

  setup do
    $per_decl_calls = []
    @global_calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @global_calls << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
    $per_decl_calls = nil
  end

  def test_per_declaration_callback_takes_precedence_over_global
    post :create, params: { trap_field: 'spam' }
    assert_response :ok
    assert_empty response.body
    assert_equal 1, $per_decl_calls.size
    assert_equal :honeypot, $per_decl_calls.first[:reason]
    assert_empty @global_calls
  end
end

class OnTrapCallbackErrorResilienceTest < ActionController::TestCase
  tests OnTrapGlobalCallbackController

  setup do
    Spamtrap.on_trap = ->(**) { raise 'callback exploded' }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_broken_callback_does_not_prevent_head_200
    post :create, params: { trap_field: 'spam' }
    assert_response :ok
    assert_empty response.body
  end
end
