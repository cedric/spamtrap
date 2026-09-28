require 'stringio'
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
  spamtrap :trap_field, mutate: :lenient, only: :create

  def create
    # Render the remapped comment param keys so tests can assert on them
    render plain: params[:comment].to_unsafe_h.keys.sort.join(',')
  end
end

class NestedMutationController < ActionController::Base
  spamtrap :trap_field, mutate: :lenient, only: :create

  def create
    # Render top-level and nested address keys to verify salt propagation
    comment_keys = params[:comment].to_unsafe_h.except('address').keys.sort
    address_keys = params.dig(:comment, :address).to_unsafe_h.keys.sort rescue []
    render plain: "#{comment_keys.join(',')};#{address_keys.join(',')}"
  end
end

module NonceTestHelper
  REMOTE_IP = '0.0.0.0'
end

class KillSwitchControllerTest < ActionController::TestCase
  tests NonceController

  teardown do
    Spamtrap.enabled = nil
  end

  def test_disabled_lets_filled_honeypot_and_missing_nonce_through
    Spamtrap.enabled = false

    post :create, params: { trap_field: 'spam' }

    assert_response :ok
    assert_equal 'success', response.body
  end
end

class NonceBindIpControllerTest < ActionController::TestCase
  tests NonceController

  teardown do
    Spamtrap.nonce_bind_ip = nil
  end

  def test_default_binds_to_the_full_ip_and_rejects_a_different_one
    timestamp = Time.now.to_i
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '10.1.2.3', at: timestamp)
    )

    @request.remote_addr = '10.1.2.4'
    post :create, params: params

    assert_response :ok
    assert_empty response.body
  end

  def test_prefix_binding_accepts_a_different_ip_in_the_same_slash_24
    Spamtrap.nonce_bind_ip = :prefix
    timestamp = Time.now.to_i
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '10.1.2.3', at: timestamp)
    )

    @request.remote_addr = '10.1.2.99'
    post :create, params: params

    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_prefix_binding_rejects_an_ip_outside_the_slash_24
    Spamtrap.nonce_bind_ip = :prefix
    timestamp = Time.now.to_i
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '10.1.2.3', at: timestamp)
    )

    @request.remote_addr = '10.1.3.3'
    post :create, params: params

    assert_response :ok
    assert_empty response.body
  end

  def test_false_binding_accepts_any_ip
    Spamtrap.nonce_bind_ip = false
    timestamp = Time.now.to_i
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '10.1.2.3', at: timestamp)
    )

    @request.remote_addr = '99.99.99.99'
    post :create, params: params

    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_prefix_binding_treats_ipv4_mapped_ipv6_as_ipv4
    Spamtrap.nonce_bind_ip = :prefix
    params = { trap_field: '' }.merge(spamtrap_nonce_params(honeypot: 'trap_field', ip: '10.1.2.3'))

    @request.remote_addr = '::ffff:10.1.2.99'
    post :create, params: params

    assert_response :ok
    assert_equal 'success', response.body
  end

end

class SingleUseNonceController < ActionController::Base
  spamtrap :trap_field, nonce: :single_use, only: :create

  def create
    render plain: 'success'
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
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp)
    )
    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_same_token_used_twice_passes_both_times
    # Documents the guarantee: the stateless (non-single_use) mode is a freshness
    # check only, not replay protection.
    timestamp = Time.now.to_i
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp)
    )

    post :create, params: params
    assert_response :ok
    assert_equal 'success', response.body

    post :create, params: params
    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_tampered_nonce_is_rejected
    timestamp = Time.now.to_i
    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      spamtrap_nonce_id: SecureRandom.hex(16),
      spamtrap_nonce: 'deadbeef'
    }
    assert_response :ok
    assert_empty response.body
  end

  def test_expired_nonce_is_rejected
    timestamp = Time.now.to_i - 7200
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp)
    )
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
    post :create, params: { trap_field: 'spam' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp)
    )
    assert_response :ok
    assert_empty response.body
  end
end

class NonceTimeoutControllerTest < ActionController::TestCase
  include NonceTestHelper
  tests NonceTimeoutController

  def test_nonce_within_custom_timeout_passes
    timestamp = Time.now.to_i - 30
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp)
    )
    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_nonce_beyond_custom_timeout_is_rejected
    timestamp = Time.now.to_i - 120
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp)
    )
    assert_response :ok
    assert_empty response.body
  end
end

class SingleUseNonceControllerTest < ActionController::TestCase
  tests SingleUseNonceController

  setup do
    Rails.cache.clear
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_valid_token_passes_once_and_is_replayed_on_second_use
    timestamp = Time.now.to_i
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp)
    )

    post :create, params: params
    assert_response :ok
    assert_equal 'success', response.body

    post :create, params: params
    assert_response :ok
    assert_empty response.body
    assert_equal [:nonce_replayed], @calls
  end

  def test_future_timestamp_beyond_skew_is_invalid
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: Time.now.to_i + 120)
    )
    post :create, params: params
    assert_response :ok
    assert_empty response.body
    assert_equal [:nonce_invalid], @calls
  end

  def test_future_timestamp_within_skew_passes
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: Time.now.to_i + 30)
    )
    post :create, params: params
    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_token_minted_for_a_different_honeypot_is_invalid
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'other_field', ip: NonceTestHelper::REMOTE_IP, at: Time.now.to_i)
    )
    post :create, params: params
    assert_response :ok
    assert_empty response.body
    assert_equal [:nonce_invalid], @calls
  end

  def test_expired_token_is_rejected
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: Time.now.to_i - 7200)
    )
    post :create, params: params
    assert_response :ok
    assert_empty response.body
    assert_equal [:nonce_expired], @calls
  end

  def test_missing_nonce_id_is_rejected
    timestamp    = Time.now.to_i
    nonce_params = spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp)
    nonce_params.delete(:spamtrap_nonce_id)

    post :create, params: { trap_field: '' }.merge(nonce_params)
    assert_response :ok
    assert_empty response.body
    assert_equal [:nonce_missing], @calls
  end

  def test_malformed_nonce_id_is_rejected
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: Time.now.to_i, nonce_id: 'zz')
    )
    post :create, params: params
    assert_response :ok
    assert_empty response.body
    assert_equal [:nonce_invalid], @calls
  end
end

class MutationControllerTest < ActionController::TestCase
  tests MutationController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_encrypted_field_names_are_remapped_to_real_names
    timestamp   = Time.now.to_i
    body_token  = spamtrap_token('body',  timestamp)
    email_token = spamtrap_token('email', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello world', email_token => 'test@example.com' }
    }

    assert_response :ok
    assert_equal 'body,email', response.body
  end

  def test_unencrypted_field_names_pass_through_unchanged
    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: Time.now.to_i,
      comment: { body: 'Hello', email: 'test@example.com' }
    }

    assert_response :ok
    assert_equal 'body,email', response.body
  end

  def test_missing_timestamp_leaves_encrypted_params_unmapped
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    refute_equal 'body', response.body
  end

  def test_wrong_timestamp_fails_to_decrypt
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp + 1,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    refute_equal 'body', response.body
  end

  # Was "leaves params unmapped": lenient mode now traps :mutation_expired too (see #2),
  # or a stale-but-decryptable token would be accepted since it now remaps successfully.
  def test_expired_timestamp_traps_as_mutation_expired_even_in_lenient_mode
    timestamp  = Time.now.to_i - Spamtrap.mutation_timeout - 10
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal [:mutation_expired], @calls
  end

  def test_future_timestamp_beyond_skew_traps_as_mutation_expired_even_in_lenient_mode
    timestamp  = Time.now.to_i + 120
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal [:mutation_expired], @calls
  end

  def test_future_timestamp_within_skew_remaps_fine
    timestamp  = Time.now.to_i + 30
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @calls
  end
end

# mutate: true is now equivalent to :strict; mutate: :lenient is the old true behaviour.
class StrictByDefaultController < ActionController::Base
  spamtrap :trap_field, mutate: true, only: :create

  def create
    render plain: 'success'
  end
end

class StrictByDefaultControllerTest < ActionController::TestCase
  tests StrictByDefaultController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_mutate_true_now_traps_plaintext_field_names
    timestamp = Time.now.to_i

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body: 'x' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal [:plaintext_field], @calls
  end
end

class StrictMutationController < ActionController::Base
  spamtrap :trap_field, mutate: :strict, only: :create

  def create
    keys = params[:comment].present? ? params[:comment].to_unsafe_h.keys.sort.join(',') : 'none'
    render plain: keys
  end
end

class StrictMutationControllerTest < ActionController::TestCase
  tests StrictMutationController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << { reason: reason, ip: request.remote_ip } }
  end

  teardown do
    Spamtrap.on_trap = nil
    Spamtrap.allowed_params = []
  end

  def test_encrypted_field_passes_and_action_sees_real_name
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @calls
  end

  def test_plaintext_field_name_is_trapped
    timestamp = Time.now.to_i

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body: 'x' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal 1, @calls.size
    assert_equal :plaintext_field, @calls.first[:reason]
  end

  def test_allowlisted_top_level_keys_pass
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      authenticity_token: 'x',
      commit: 'Save',
      utf8: '✓',
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @calls
  end

  def test_allowed_params_permits_extra_top_level_key
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)
    Spamtrap.allowed_params = ['locale']

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      locale: 'en',
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @calls
  end

  def test_recaptcha_response_param_is_allowlisted
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      'g-recaptcha-response' => 'abc',
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @calls
  end

  def test_hcaptcha_response_param_is_allowlisted
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      'h-captcha-response' => 'abc',
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @calls
  end

  def test_turnstile_response_param_is_allowlisted
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      'cf-turnstile-response' => 'abc',
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @calls
  end

  def test_filled_honeypot_on_expired_render_still_reports_honeypot
    timestamp  = Time.now.to_i - Spamtrap.mutation_timeout - 10
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: 'spam',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal :honeypot, @calls.first[:reason]
  end

  def test_unlisted_top_level_key_traps_without_allowed_params
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      locale: 'en',
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal :plaintext_field, @calls.first[:reason]
  end

  def test_nested_plaintext_under_encrypted_parent_traps
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'x', extra: 'y' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal :plaintext_field, @calls.first[:reason]
  end

  def test_missing_timestamp_traps_as_mutation_expired
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      comment: { body_token => 'x' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal :mutation_expired, @calls.first[:reason]
  end

  def test_expired_timestamp_traps_as_mutation_expired
    timestamp  = Time.now.to_i - Spamtrap.mutation_timeout - 10
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'x' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal :mutation_expired, @calls.first[:reason]
  end

  def test_multi_parameter_date_select_keys_are_accepted
    timestamp       = Time.now.to_i
    published_token = spamtrap_token('published_on', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: {
        "#{published_token}(1i)" => '2026',
        "#{published_token}(2i)" => '9',
        "#{published_token}(3i)" => '27'
      }
    }

    assert_response :ok
    assert_equal 'published_on(1i),published_on(2i),published_on(3i)', response.body
    assert_empty @calls
  end
end

# Controllers exercising #2: on :mutation_expired, params are remapped before the trap
# response/on_trap callback runs, so the app can re-render the form with the user's input.
class MutationExpiredTrapResponseController < ActionController::Base
  spamtrap :trap_field, mutate: true,
    trap_response: ->(controller, reason) {
      Thread.current[:mutation_expired_trap_response] = { reason: reason, comment: controller.params[:comment] }
      controller.head :unprocessable_entity
    },
    only: :create

  def create
    render plain: 'success'
  end
end

class MutationExpiredTrapResponseControllerTest < ActionController::TestCase
  tests MutationExpiredTrapResponseController

  setup do
    Thread.current[:mutation_expired_trap_response] = nil
  end

  teardown do
    Thread.current[:mutation_expired_trap_response] = nil
  end

  def test_trap_response_callable_receives_remapped_params_on_expiry
    timestamp  = Time.now.to_i - Spamtrap.mutation_timeout - 10
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello world' }
    }

    assert_response :unprocessable_entity
    captured = Thread.current[:mutation_expired_trap_response]
    assert_equal :mutation_expired, captured[:reason]
    assert_equal 'Hello world', captured[:comment][:body]
  end

  # Hours past expiry, not just barely past it: still remapped for the trap path, and still rejected.
  def test_far_expired_token_is_still_remapped_and_still_rejected
    timestamp  = Time.now.to_i - (10 * Spamtrap.mutation_timeout)
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello world' }
    }

    assert_response :unprocessable_entity
    captured = Thread.current[:mutation_expired_trap_response]
    assert_equal :mutation_expired, captured[:reason]
    assert_equal 'Hello world', captured[:comment][:body]
  end
end

class MutationExpiredOnTrapController < ActionController::Base
  spamtrap :trap_field, mutate: true,
    on_trap: ->(reason:, params:) { Thread.current[:mutation_expired_on_trap] = { reason: reason, comment: params[:comment] } },
    only: :create

  def create
    render plain: 'success'
  end
end

class MutationExpiredOnTrapControllerTest < ActionController::TestCase
  tests MutationExpiredOnTrapController

  setup do
    Thread.current[:mutation_expired_on_trap] = nil
  end

  teardown do
    Thread.current[:mutation_expired_on_trap] = nil
  end

  def test_on_trap_receives_remapped_params_on_expiry
    timestamp  = Time.now.to_i - Spamtrap.mutation_timeout - 10
    body_token = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello world' }
    }

    assert_response :ok
    captured = Thread.current[:mutation_expired_on_trap]
    assert_equal :mutation_expired, captured[:reason]
    assert_equal 'Hello world', captured[:comment][:body]
  end
end

# Exercises Spamtrap::TestHelper's spamtrap_params against a strict + nonce action, the
# way an app's own controller test would.
class StrictMutationNonceController < ActionController::Base
  spamtrap :trap_field, mutate: :strict, nonce: true, only: :create

  def create
    keys = params[:comment].present? ? params[:comment].to_unsafe_h.keys.sort.join(',') : 'none'
    render plain: keys
  end
end

class StrictMutationNonceControllerTest < ActionController::TestCase
  tests StrictMutationNonceController

  def test_spamtrap_params_helper_passes_the_whole_gauntlet
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)

    params = spamtrap_params(honeypot: 'trap_field', nonce: true, mutate: true, at: timestamp)
      .merge(comment: { body_token => 'Hello' })

    post :create, params: params

    assert_response :ok
    assert_equal 'body', response.body
  end
end

class NestedMutationControllerTest < ActionController::TestCase
  tests NestedMutationController

  def test_timestamp_propagates_to_fields_for_child_builder
    timestamp    = Time.now.to_i
    body_token   = spamtrap_token('body',   timestamp)
    street_token = spamtrap_token('street', timestamp)
    city_token   = spamtrap_token('city',   timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
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

# Renders the raw params it received (not just keys) so round-trip and
# nested-array remapping tests can assert on actual values.
class MutationEchoController < ActionController::Base
  spamtrap :trap_field, mutate: :lenient, only: :create

  def create
    render plain: params[:comment].to_unsafe_h.to_json
  end
end

class MutationRenderRoundTripTest < ActionController::TestCase
  tests MutationEchoController

  def test_rendered_form_round_trips_through_the_controller
    html = ActionController::Base.render(inline: <<~ERB)
      <%= form_for :comment, url: '/mutation_echo/create' do |f| %>
        <%= f.spamtrap :trap_field, mutate: true %>
        <%= f.text_field :body %>
        <%= f.email_field :email %>
      <% end %>
    ERB

    tags      = html.scan(/<input[^>]*>/)
    fields    = tags.map { |t| [t[/name="([^"]*)"/, 1], t[/value="([^"]*)"/, 1]] }.to_h
    timestamp = fields['spamtrap_timestamp']

    real_values = { body: 'hello', email: 'a@b.c' }
    comment_params = fields.keys.each_with_object({}) do |name, memo|
      token = name && name[/\Acomment\[(.+)\]\z/, 1]
      next unless token

      real = spamtrap_decrypt(token, timestamp)
      memo[token] = real_values[real]
    end

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: comment_params
    }

    assert_response :ok
    parsed = JSON.parse(response.body)
    assert_equal 'hello', parsed['body']
    assert_equal 'a@b.c', parsed['email']
  end
end

class NestedArrayMutationTest < ActionController::TestCase
  tests MutationEchoController

  def test_array_elements_are_remapped
    timestamp  = Time.now.to_i
    tags_token = spamtrap_token('tags', timestamp)
    name_token = spamtrap_token('name', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { tags_token => [{ name_token => 'x' }] }
    }

    assert_response :ok
    parsed = JSON.parse(response.body)
    assert_equal 'x', parsed['tags'][0]['name']
  end
end

class MultiParameterMutationTest < ActionController::TestCase
  tests MutationEchoController

  def test_multi_parameter_date_select_keys_are_remapped
    timestamp       = Time.now.to_i
    published_token = spamtrap_token('published_on', timestamp)

    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: {
        "#{published_token}(1i)" => '2026',
        "#{published_token}(2i)" => '9',
        "#{published_token}(3i)" => '27'
      }
    }

    assert_response :ok
    parsed = JSON.parse(response.body)
    assert_equal '2026', parsed['published_on(1i)']
    assert_equal '9',    parsed['published_on(2i)']
    assert_equal '27',   parsed['published_on(3i)']
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
  include NonceTestHelper
  tests GlobalDefaultsController

  setup do
    Spamtrap.nonce  = true
    Spamtrap.mutate = :lenient
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
      comment: { spamtrap_token('body', timestamp) => 'Hello' }
    }.merge(spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp))
    assert_response :ok
    assert_equal 'body', response.body
  end

  def test_global_mutate_default_remaps_encrypted_fields
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp)
    post :create, params: {
      trap_field: '',
      comment: { body_token => 'Hello' }
    }.merge(spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp))
    assert_response :ok
    assert_equal 'body', response.body
  end
end

class GlobalSingleUseNonceControllerTest < ActionController::TestCase
  tests GlobalDefaultsController

  setup do
    Rails.cache.clear
    Spamtrap.nonce = :single_use
  end

  teardown do
    Spamtrap.nonce = false
  end

  def test_global_single_use_default_is_honoured_without_an_explicit_nonce_option
    timestamp = Time.now.to_i
    params = { trap_field: '', comment: { body: 'Hello' } }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp)
    )

    post :create, params: params
    assert_response :ok
    assert_equal 'body', response.body

    post :create, params: params
    assert_response :ok
    assert_empty response.body
  end
end

class GlobalOverrideControllerTest < ActionController::TestCase
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
      spamtrap_timestamp: Time.now.to_i,
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
    on_trap: ->(reason:, request:) { Thread.current[:per_decl_calls] << { reason: reason, ip: request.remote_ip } }

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
    assert_equal :nonce_missing, @calls.first[:reason]
  end
end

class OnTrapPerDeclarationCallbackTest < ActionController::TestCase
  tests OnTrapPerDeclarationController

  setup do
    Thread.current[:per_decl_calls] = []
    @global_calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @global_calls << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
    Thread.current[:per_decl_calls] = nil
  end

  def test_per_declaration_callback_takes_precedence_over_global
    post :create, params: { trap_field: 'spam' }
    assert_response :ok
    assert_empty response.body
    assert_equal 1, Thread.current[:per_decl_calls].size
    assert_equal :honeypot, Thread.current[:per_decl_calls].first[:reason]
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

# Controllers for trap_response tests.
class TrapResponseUnprocessableController < ActionController::Base
  spamtrap :trap_field, trap_response: :unprocessable, only: :create

  def create
    render plain: 'success'
  end
end

class TrapResponseGlobalController < ActionController::Base
  spamtrap :trap_field, only: :create

  def create
    render plain: 'success'
  end
end

class TrapResponseOverrideController < ActionController::Base
  spamtrap :trap_field, trap_response: :head, only: :create

  def create
    render plain: 'success'
  end
end

class TrapResponseHashNonceController < ActionController::Base
  spamtrap :trap_field, nonce: true, trap_response: { honeypot: :head, nonce_expired: :unprocessable }, only: :create

  def create
    render plain: 'success'
  end
end

class TrapResponseCallableController < ActionController::Base
  spamtrap :trap_field, trap_response: ->(controller, reason) { controller.render plain: "trapped:#{reason}", status: 403 }, only: :create

  def create
    render plain: 'success'
  end
end

class TrapResponseRedirectBackController < ActionController::Base
  spamtrap :trap_field, trap_response: :redirect_back, only: :create

  def create
    render plain: 'success'
  end
end

class TrapResponseOnTrapRedirectController < ActionController::Base
  spamtrap :trap_field, on_trap: ->(controller:, reason:) { controller.redirect_to('/sorry') }, only: :create

  def create
    render plain: 'success'
  end
end

class TrapResponseOnTrapPayloadController < ActionController::Base
  spamtrap :trap_field, on_trap: ->(**kw) { Thread.current[:on_trap_payload] = kw }, only: :create

  def create
    render plain: 'success'
  end
end

class TrapResponseBogusController < ActionController::Base
  spamtrap :trap_field, trap_response: :bogus, only: :create

  def create
    render plain: 'success'
  end
end

class TrapResponseUnprocessableControllerTest < ActionController::TestCase
  tests TrapResponseUnprocessableController

  def test_per_action_unprocessable_response_on_honeypot_trap
    post :create, params: { trap_field: 'spam' }
    assert_response :unprocessable_entity
  end
end

class TrapResponseGlobalControllerTest < ActionController::TestCase
  tests TrapResponseGlobalController

  setup do
    Spamtrap.trap_response = :no_content
  end

  teardown do
    Spamtrap.trap_response = nil
  end

  def test_global_trap_response_is_used_when_no_per_action_option
    post :create, params: { trap_field: 'spam' }
    assert_response :no_content
  end
end

class TrapResponseOverrideControllerTest < ActionController::TestCase
  tests TrapResponseOverrideController

  setup do
    Spamtrap.trap_response = :no_content
  end

  teardown do
    Spamtrap.trap_response = nil
  end

  def test_per_action_head_overrides_global_no_content
    post :create, params: { trap_field: 'spam' }
    assert_response :ok
    assert_empty response.body
  end
end

class TrapResponseHashNonceControllerTest < ActionController::TestCase
  include NonceTestHelper
  tests TrapResponseHashNonceController

  def test_hash_form_uses_honeypot_entry_for_honeypot_trap
    post :create, params: { trap_field: 'spam' }
    assert_response :ok
    assert_empty response.body
  end

  def test_hash_form_uses_nonce_expired_entry_for_expired_nonce
    timestamp = Time.now.to_i - 3600
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: NonceTestHelper::REMOTE_IP, at: timestamp)
    )
    assert_response :unprocessable_entity
  end
end

class TrapResponseCallableControllerTest < ActionController::TestCase
  tests TrapResponseCallableController

  def test_callable_trap_response_renders_its_own_body_and_status
    post :create, params: { trap_field: 'spam' }
    assert_response :forbidden
    assert_equal 'trapped:honeypot', response.body
  end
end

class TrapResponseRedirectBackControllerTest < ActionController::TestCase
  tests TrapResponseRedirectBackController

  def test_redirect_back_with_referer_redirects_there
    @request.env['HTTP_REFERER'] = 'http://test.host/back'
    post :create, params: { trap_field: 'spam' }
    assert_response 303
    assert_redirected_to 'http://test.host/back'
  end

  def test_redirect_back_without_referer_redirects_to_root
    post :create, params: { trap_field: 'spam' }
    assert_response 303
    assert_redirected_to '/'
  end
end

class TrapResponseOnTrapRedirectControllerTest < ActionController::TestCase
  tests TrapResponseOnTrapRedirectController

  def test_on_trap_redirect_short_circuits_the_default_trap_response
    post :create, params: { trap_field: 'spam' }
    assert_redirected_to '/sorry'
  end
end

# The honeypot's own field name is encrypted under mutate: true/:strict; posting it
# filled under its encrypted name must still trap, and posting it empty must still pass.
class StrictMutationHoneypotOwnNameTest < ActionController::TestCase
  tests StrictMutationController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << { reason: reason, ip: request.remote_ip } }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_honeypot_filled_under_its_encrypted_name_is_trapped
    timestamp     = Time.now.to_i
    honeypot_name = spamtrap_token('trap_field', timestamp)
    body_token    = spamtrap_token('body', timestamp)

    post :create, params: {
      honeypot_name => 'bot text',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal 1, @calls.size
    assert_equal :honeypot, @calls.first[:reason]
  end

  def test_honeypot_empty_under_its_encrypted_name_passes
    timestamp     = Time.now.to_i
    honeypot_name = spamtrap_token('trap_field', timestamp)
    body_token    = spamtrap_token('body', timestamp)

    post :create, params: {
      honeypot_name => '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @calls
  end
end

# Same as above, on the lenient (mutate: :lenient) controller: mutate: :lenient still
# mutates the honeypot's own name (only :strict/:true adds the plaintext-field trap).
class LenientMutationHoneypotOwnNameTest < ActionController::TestCase
  tests MutationController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << { reason: reason, ip: request.remote_ip } }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_honeypot_filled_under_its_encrypted_name_is_trapped
    timestamp     = Time.now.to_i
    honeypot_name = spamtrap_token('trap_field', timestamp)
    body_token    = spamtrap_token('body', timestamp)

    post :create, params: {
      honeypot_name => 'bot text',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal 1, @calls.size
    assert_equal :honeypot, @calls.first[:reason]
  end

  def test_honeypot_empty_under_its_encrypted_name_passes
    timestamp     = Time.now.to_i
    honeypot_name = spamtrap_token('trap_field', timestamp)
    body_token    = spamtrap_token('body', timestamp)

    post :create, params: {
      honeypot_name => '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @calls
  end
end

# Render-to-parse: the honeypot textarea f.spamtrap renders under mutate: true must post
# back under its encrypted name and still be caught, mirroring MutationRenderRoundTripTest.
class MutationRenderRoundTripHoneypotOwnNameTest < ActionController::TestCase
  tests MutationEchoController

  def render_form
    ActionController::Base.render(inline: <<~ERB)
      <%= form_for :comment, url: '/mutation_echo/create' do |f| %>
        <%= f.spamtrap :trap_field, mutate: true %>
        <%= f.text_field :body %>
      <% end %>
    ERB
  end

  def test_rendered_honeypot_filled_under_its_encrypted_name_is_trapped
    html = render_form

    honeypot_tag  = html[/<textarea[^>]*>/]
    honeypot_name = honeypot_tag[/name="([^"]+)"/, 1]
    timestamp_tag = html[/<input[^>]*name="spamtrap_timestamp"[^>]*>/]
    timestamp     = timestamp_tag[/value="([^"]*)"/, 1]
    body_tag      = html[/<input[^>]*name="comment\[[^\]]+\]"[^>]*>/]
    body_token    = body_tag[/name="comment\[([^\]]+)\]"/, 1]

    refute_equal 'trap_field', honeypot_name
    assert_equal :trap_field, spamtrap_decrypt(honeypot_name, timestamp)

    post :create, params: {
      honeypot_name => 'bot text',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'hello' }
    }

    assert_response :ok
    assert_empty response.body
  end

  def test_rendered_honeypot_empty_under_its_encrypted_name_passes
    html = render_form

    honeypot_tag  = html[/<textarea[^>]*>/]
    honeypot_name = honeypot_tag[/name="([^"]+)"/, 1]
    timestamp_tag = html[/<input[^>]*name="spamtrap_timestamp"[^>]*>/]
    timestamp     = timestamp_tag[/value="([^"]*)"/, 1]
    body_tag      = html[/<input[^>]*name="comment\[[^\]]+\]"[^>]*>/]
    body_token    = body_tag[/name="comment\[([^\]]+)\]"/, 1]

    post :create, params: {
      honeypot_name => '',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'hello' }
    }

    assert_response :ok
    parsed = JSON.parse(response.body)
    assert_equal 'hello', parsed['body']
  end
end

class TrapResponseOnTrapPayloadControllerTest < ActionController::TestCase
  tests TrapResponseOnTrapPayloadController

  setup do
    Thread.current[:on_trap_payload] = nil
  end

  teardown do
    Thread.current[:on_trap_payload] = nil
  end

  def test_on_trap_receives_controller_honeypot_and_params
    post :create, params: { trap_field: 'spam' }
    payload = Thread.current[:on_trap_payload]
    assert_kind_of TrapResponseOnTrapPayloadController, payload[:controller]
    assert_equal 'trap_field', payload[:honeypot]
    assert_equal 'spam', payload[:params][:trap_field]
  end
end

class TrapResponseBogusControllerTest < ActionController::TestCase
  tests TrapResponseBogusController

  def test_unknown_trap_response_raises_argument_error
    assert_raises(ArgumentError) do
      post :create, params: { trap_field: 'spam' }
    end
  end
end

# Exercises Spamtrap::TestHelper#spamtrap_mutate and spamtrap_params(fields:) against a
# real strict action, echoing back the whole params hash (not just top-level keys) so
# nested/array/multi-parameter round-tripping can be asserted on.
class StrictMutationEchoController < ActionController::Base
  spamtrap :trap_field, mutate: :strict, only: :create

  def create
    render plain: params.to_unsafe_h.except('controller', 'action').to_json
  end
end

class SpamtrapMutateTestHelperTest < ActionController::TestCase
  tests StrictMutationEchoController

  def test_nested_object_arrives_with_real_names_and_is_not_trapped
    timestamp = Time.now.to_i
    fields = { comment: { body: 'Hello', address: { street: '123 Main St', city: 'Springfield' } } }

    post :create, params: { trap_field: '', spamtrap_timestamp: timestamp }.merge(spamtrap_mutate(fields, at: timestamp))

    assert_response :ok
    parsed = JSON.parse(response.body)
    assert_equal 'Hello', parsed['comment']['body']
    assert_equal '123 Main St', parsed['comment']['address']['street']
    assert_equal 'Springfield', parsed['comment']['address']['city']
  end

  # Rack's indexless `a[][k]` encoding starts a new record only when a key repeats, so this
  # depends on one token per field name per render.
  def test_array_of_nested_objects_arrives_with_real_names_and_is_not_trapped
    timestamp = Time.now.to_i
    fields = { comment: { recipients: [{ name: 'Alice', email: 'a@x.test' }, { name: 'Bob', email: 'b@x.test' }] } }

    post :create, params: { trap_field: '', spamtrap_timestamp: timestamp }.merge(spamtrap_mutate(fields, at: timestamp))

    assert_response :ok
    parsed = JSON.parse(response.body)
    assert_equal [%w[Alice a@x.test], %w[Bob b@x.test]], parsed['comment']['recipients'].map { |r| [r['name'], r['email']] }
  end

  def test_multi_parameter_date_select_field_arrives_with_real_names_and_is_not_trapped
    timestamp = Time.now.to_i
    fields = { comment: { 'published_on(1i)' => '2026', 'published_on(2i)' => '9', 'published_on(3i)' => '27' } }

    post :create, params: { trap_field: '', spamtrap_timestamp: timestamp }.merge(spamtrap_mutate(fields, at: timestamp))

    assert_response :ok
    parsed = JSON.parse(response.body)
    assert_equal '2026', parsed['comment']['published_on(1i)']
    assert_equal '9',    parsed['comment']['published_on(2i)']
    assert_equal '27',   parsed['comment']['published_on(3i)']
  end

  def test_array_of_scalars_field_arrives_with_real_name_and_is_not_trapped
    timestamp = Time.now.to_i
    fields = { comment: { tags: %w[ruby rails] } }

    post :create, params: { trap_field: '', spamtrap_timestamp: timestamp }.merge(spamtrap_mutate(fields, at: timestamp))

    assert_response :ok
    parsed = JSON.parse(response.body)
    assert_equal %w[ruby rails], parsed['comment']['tags']
  end

  def test_spamtrap_params_with_fields_posts_the_whole_gauntlet
    timestamp = Time.now.to_i

    params = spamtrap_params(honeypot: 'trap_field', mutate: true, at: timestamp,
                              fields: { comment: { body: 'Hello', email: 'test@example.com' } })

    post :create, params: params

    assert_response :ok
    parsed = JSON.parse(response.body)
    assert_equal 'Hello', parsed['comment']['body']
    assert_equal 'test@example.com', parsed['comment']['email']
  end
end

# Controllers for the min_fill_time tests.
class FillTimeController < ActionController::Base
  spamtrap :trap_field, nonce: true, min_fill_time: 1, only: :create

  def create
    render plain: 'success'
  end
end

class FillTimeDisabledController < ActionController::Base
  spamtrap :trap_field, nonce: true, min_fill_time: false, only: :create

  def create
    render plain: 'success'
  end
end

# No per-action min_fill_time, so it relies entirely on Spamtrap.min_fill_time.
class FillTimeGlobalController < ActionController::Base
  spamtrap :trap_field, nonce: true, only: :create

  def create
    render plain: 'success'
  end
end

class FillTimeControllerTest < ActionController::TestCase
  tests FillTimeController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_nonce_minted_just_now_traps_as_too_fast
    timestamp = Time.now.to_i
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp)
    )
    assert_response :ok
    assert_empty response.body
    assert_equal [:too_fast], @calls
  end

  def test_nonce_minted_two_seconds_ago_passes
    timestamp = Time.now.to_i - 2
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp)
    )
    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_filled_honeypot_reports_honeypot_not_too_fast
    timestamp = Time.now.to_i
    post :create, params: { trap_field: 'spam' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp)
    )
    assert_response :ok
    assert_empty response.body
    assert_equal [:honeypot], @calls
  end
end

class FillTimeDisabledControllerTest < ActionController::TestCase
  tests FillTimeDisabledController

  def test_min_fill_time_false_on_the_action_passes_at_now
    timestamp = Time.now.to_i
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp)
    )
    assert_response :ok
    assert_equal 'success', response.body
  end
end

class FillTimeGlobalControllerTest < ActionController::TestCase
  tests FillTimeGlobalController

  teardown do
    # Restore the suite-wide baseline (test_helper.rb), not the gem's own default of 1.
    Spamtrap.min_fill_time = false
  end

  def test_global_min_fill_time_applies_to_an_action_with_no_per_action_value
    Spamtrap.min_fill_time = 3
    timestamp = Time.now.to_i - 1
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp)
    )
    assert_response :ok
    assert_empty response.body
  end
end

# Controller for the trap.spamtrap ActiveSupport::Notifications test.
class InstrumentationControllerTest < ActionController::TestCase
  tests HoneypotController

  def test_trap_publishes_a_notification_event
    events   = []
    callback = ->(*, payload) { events << payload }

    ActiveSupport::Notifications.subscribed(callback, 'trap.spamtrap') do
      post :create, params: { trap_field: 'spam' }
    end

    assert_equal 1, events.size
    payload = events.first
    assert_equal :honeypot, payload[:reason]
    assert_equal 'honeypot', payload[:controller]
    assert_equal 'create', payload[:action]
    assert_equal '0.0.0.0', payload[:ip]
  end

  def test_legitimate_request_publishes_no_notification
    events   = []
    callback = ->(*, payload) { events << payload }

    ActiveSupport::Notifications.subscribed(callback, 'trap.spamtrap') do
      post :create, params: { trap_field: '' }
    end

    assert_empty events
  end
end

class NormalizeIpTest < Minitest::Test
  def test_true_mode_returns_the_full_ip
    assert_equal '10.1.2.3', Spamtrap.normalize_ip('10.1.2.3', true)
  end

  def test_false_mode_returns_an_empty_string
    assert_equal '', Spamtrap.normalize_ip('10.1.2.3', false)
  end

  def test_prefix_mode_masks_ipv4_to_a_slash_24
    assert_equal '10.1.2.0/24', Spamtrap.normalize_ip('10.1.2.99', :prefix)
  end

  def test_prefix_mode_unmaps_an_ipv4_mapped_ipv6_address_first
    assert_equal '10.1.2.0/24', Spamtrap.normalize_ip('::ffff:10.1.2.99', :prefix)
  end

  def test_default_mode_reads_spamtrap_nonce_bind_ip
    Spamtrap.nonce_bind_ip = :prefix
    assert_equal '10.1.2.0/24', Spamtrap.normalize_ip('10.1.2.99')
  ensure
    Spamtrap.nonce_bind_ip = nil
  end
end

class ThrottleKeyTest < Minitest::Test
  FakeRequest = Struct.new(:remote_ip)

  def test_builds_a_key_from_the_normalized_ip
    assert_equal 'spamtrap:10.1.2.3', Spamtrap.throttle_key(FakeRequest.new('10.1.2.3'))
  end

  def test_uses_the_configured_bind_ip_mode
    Spamtrap.nonce_bind_ip = :prefix
    assert_equal 'spamtrap:10.1.2.0/24', Spamtrap.throttle_key(FakeRequest.new('10.1.2.99'))
  ensure
    Spamtrap.nonce_bind_ip = nil
  end
end

# Task 4: key rotation. secret_key_base/previous_secret_key_base let a token minted under
# the old secret keep working while both are configured, and stop working once it isn't.
class KeyRotationTest < Minitest::Test
  include Spamtrap::TestHelper

  OLD_SECRET = 'old' * 22
  NEW_SECRET = 'new' * 22

  def teardown
    Spamtrap.secret_key_base = nil
    Spamtrap.previous_secret_key_base = nil
  end

  def test_mutation_token_decrypts_with_the_previous_secret_after_rotation
    Spamtrap.secret_key_base = OLD_SECRET
    timestamp = Time.now.to_i
    token = spamtrap_token('body', timestamp)

    Spamtrap.secret_key_base = NEW_SECRET
    Spamtrap.previous_secret_key_base = OLD_SECRET

    assert_equal :body, spamtrap_decrypt(token, timestamp)
  end

  def test_mutation_token_fails_to_decrypt_without_the_previous_secret
    Spamtrap.secret_key_base = OLD_SECRET
    timestamp = Time.now.to_i
    token = spamtrap_token('body', timestamp)

    Spamtrap.secret_key_base = NEW_SECRET

    assert_nil spamtrap_decrypt(token, timestamp)
  end
end

class NonceKeyRotationControllerTest < ActionController::TestCase
  tests NonceController

  OLD_SECRET = 'old' * 22
  NEW_SECRET = 'new' * 22

  teardown do
    Spamtrap.secret_key_base = nil
    Spamtrap.previous_secret_key_base = nil
  end

  def test_nonce_minted_under_the_old_secret_verifies_after_rotation
    Spamtrap.secret_key_base = OLD_SECRET
    timestamp = Time.now.to_i - 5
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp)
    )

    Spamtrap.secret_key_base = NEW_SECRET
    Spamtrap.previous_secret_key_base = OLD_SECRET

    post :create, params: params
    assert_response :ok
    assert_equal 'success', response.body
  end

  def test_nonce_minted_under_the_old_secret_fails_without_the_previous_secret
    Spamtrap.secret_key_base = OLD_SECRET
    timestamp = Time.now.to_i - 5
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp)
    )

    Spamtrap.secret_key_base = NEW_SECRET

    post :create, params: params
    assert_response :ok
    assert_empty response.body
  end
end

# Task 5: nonce_bind_ip per action.
class NonceBindIpActionController < ActionController::Base
  spamtrap :trap_field, nonce: true, nonce_bind_ip: :prefix, only: :create

  def create
    render plain: 'success'
  end
end

class NonceBindIpActionControllerTest < ActionController::TestCase
  tests NonceBindIpActionController

  def test_per_action_prefix_binding_accepts_a_different_ip_in_the_same_slash_24_while_global_stays_true
    assert_equal true, Spamtrap.nonce_bind_ip

    timestamp = Time.now.to_i - 5
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '10.1.2.3', at: timestamp, bind_ip: :prefix)
    )

    @request.remote_addr = '10.1.2.99'
    post :create, params: params

    assert_response :ok
    assert_equal 'success', response.body
  end
end

# Task 5: API controllers.
class ApiHoneypotController < ActionController::API
  spamtrap :trap_field, only: :create

  def create
    render plain: 'success'
  end
end

class ApiHoneypotControllerTest < ActionController::TestCase
  tests ApiHoneypotController

  def test_filled_honeypot_traps
    post :create, params: { trap_field: 'spam' }
    assert_response :ok
    assert_empty response.body
  end

  def test_empty_honeypot_passes
    post :create, params: { trap_field: '' }
    assert_response :ok
    assert_equal 'success', response.body
  end
end

# Mutation-only forms have no nonce path, so the fill-time check runs on its own branch.
class MutationOnlyFillTimeTest < ActionController::TestCase
  tests StrictMutationController

  setup do
    @reasons = []
    Spamtrap.on_trap = ->(reason:) { @reasons << reason }
    Spamtrap.min_fill_time = 1
  end

  teardown do
    Spamtrap.on_trap = nil
    Spamtrap.min_fill_time = false # suite-wide baseline from test_helper
  end

  def post_with_timestamp(timestamp)
    post :create, params: {
      trap_field: '',
      spamtrap_timestamp: timestamp,
      comment: { spamtrap_token('body', timestamp) => 'Hello' }
    }
  end

  def test_submission_in_the_same_second_as_render_is_too_fast
    post_with_timestamp(Time.now.to_i)
    assert_response :ok
    assert_empty response.body
    assert_equal [:too_fast], @reasons
  end

  def test_submission_two_seconds_after_render_passes
    post_with_timestamp(Time.now.to_i - 2)
    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @reasons
  end
end

# Task 1: honeypot decoys. StrictMutationController checks all three of
# Spamtrap.honeypot_fields regardless of which style(s) the view rendered.
class StrictMutationHoneypotDecoyTest < ActionController::TestCase
  tests StrictMutationController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_filled_text_decoy_traps
    timestamp = Time.now.to_i
    post :create, params: {
      trap_field: '', trap_field_input: 'bot text', trap_field_check: '',
      spamtrap_timestamp: timestamp,
      comment: { spamtrap_token('body', timestamp) => 'Hello' }
    }
    assert_response :ok
    assert_empty response.body
    assert_equal [:honeypot], @calls
  end

  def test_checked_checkbox_decoy_traps
    timestamp = Time.now.to_i
    post :create, params: {
      trap_field: '', trap_field_input: '', trap_field_check: '1',
      spamtrap_timestamp: timestamp,
      comment: { spamtrap_token('body', timestamp) => 'Hello' }
    }
    assert_response :ok
    assert_empty response.body
    assert_equal [:honeypot], @calls
  end

  def test_all_decoys_empty_passes
    timestamp = Time.now.to_i
    post :create, params: {
      trap_field: '', trap_field_input: '', trap_field_check: '',
      spamtrap_timestamp: timestamp,
      comment: { spamtrap_token('body', timestamp) => 'Hello' }
    }
    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @calls
  end

  def test_filled_decoy_under_its_encrypted_name_traps
    timestamp     = Time.now.to_i
    decoy_name    = spamtrap_token('trap_field_input', timestamp)
    body_token    = spamtrap_token('body', timestamp)

    post :create, params: {
      trap_field: '',
      decoy_name => 'bot text',
      spamtrap_timestamp: timestamp,
      comment: { body_token => 'Hello' }
    }

    assert_response :ok
    assert_empty response.body
    assert_equal [:honeypot], @calls
  end
end

# Task 2: JS proof of presence.
class JsProofController < ActionController::Base
  spamtrap :trap_field, nonce: true, js_proof: true, only: :create

  def create
    render plain: 'success'
  end
end

class JsProofControllerTest < ActionController::TestCase
  tests JsProofController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_missing_js_field_traps_as_no_js
    timestamp = Time.now.to_i - 5
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp)
    )
    post :create, params: params
    assert_response :ok
    assert_empty response.body
    assert_equal [:no_js], @calls
  end

  def test_wrong_js_value_traps_as_no_js
    timestamp = Time.now.to_i - 5
    params = { trap_field: '', spamtrap_js: 'bogus' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp)
    )
    post :create, params: params
    assert_response :ok
    assert_empty response.body
    assert_equal [:no_js], @calls
  end

  def test_valid_js_param_passes
    timestamp = Time.now.to_i - 5
    params = { trap_field: '' }
      .merge(spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp))
      .merge(spamtrap_js_param(honeypot: 'trap_field', at: timestamp))
    post :create, params: params
    assert_response :ok
    assert_equal 'success', response.body
    assert_empty @calls
  end
end

class JsProofGlobalControllerTest < ActionController::TestCase
  tests NonceController

  setup do
    Spamtrap.js_proof = true
  end

  teardown do
    Spamtrap.js_proof = false
  end

  def test_global_js_proof_applies_to_an_action_without_the_option
    timestamp = Time.now.to_i - 5
    params = { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp)
    )
    post :create, params: params
    assert_response :ok
    assert_empty response.body
  end
end

class JsProofSpamtrapParamsHelperTest < ActionController::TestCase
  tests JsProofController

  def test_spamtrap_params_helper_passes_the_whole_gauntlet
    timestamp = Time.now.to_i - 5
    params = spamtrap_params(honeypot: 'trap_field', nonce: true, js_proof: true, at: timestamp)
    post :create, params: params
    assert_response :ok
    assert_equal 'success', response.body
  end
end

# Task 3: content hook. A truthy suspicious_if is the last check, run after every other one.
class ContentHookController < ActionController::Base
  spamtrap :trap_field, only: :create,
    suspicious_if: ->(params) { params[:comment][:body].to_s.include?('http') }

  def create
    render plain: 'success'
  end
end

class ContentHookControllerTest < ActionController::TestCase
  tests ContentHookController

  setup do
    @calls = []
    Spamtrap.on_trap = ->(reason:, request:) { @calls << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
  end

  def test_body_containing_a_link_is_trapped_as_content
    post :create, params: { trap_field: '', comment: { body: 'check out http://spam.example' } }
    assert_response :ok
    assert_empty response.body
    assert_equal [:content], @calls
  end

  def test_body_without_a_link_passes
    post :create, params: { trap_field: '', comment: { body: 'a normal comment' } }
    assert_response :ok
    assert_equal 'success', response.body
    assert_empty @calls
  end
end

class ContentHookKeywordController < ActionController::Base
  spamtrap :trap_field, only: :create,
    suspicious_if: ->(request:, **) { request.remote_ip == '9.9.9.9' }

  def create
    render plain: 'success'
  end
end

class ContentHookKeywordControllerTest < ActionController::TestCase
  tests ContentHookKeywordController

  def test_matching_remote_ip_is_trapped
    @request.remote_addr = '9.9.9.9'
    post :create, params: { trap_field: '' }
    assert_response :ok
    assert_empty response.body
  end

  def test_non_matching_remote_ip_passes
    @request.remote_addr = '1.2.3.4'
    post :create, params: { trap_field: '' }
    assert_response :ok
    assert_equal 'success', response.body
  end
end

class ContentHookRaisingController < ActionController::Base
  spamtrap :trap_field, only: :create, suspicious_if: ->(params) { raise 'boom' }

  def create
    render plain: 'success'
  end
end

class ContentHookRaisingControllerTest < ActionController::TestCase
  tests ContentHookRaisingController

  def test_raising_hook_logs_and_passes
    io = StringIO.new
    original_logger = Rails.logger
    Rails.logger = Logger.new(io)

    post :create, params: { trap_field: '' }

    assert_response :ok
    assert_equal 'success', response.body
    assert_match(/boom/, io.string)
  ensure
    Rails.logger = original_logger
  end
end

class ContentHookNotCalledController < ActionController::Base
  spamtrap :trap_field, only: :create,
    suspicious_if: ->(params) { Thread.current[:content_hook_calls] += 1; false }

  def create
    render plain: 'success'
  end
end

class ContentHookNotCalledOnEarlierTrapTest < ActionController::TestCase
  tests ContentHookNotCalledController

  setup do
    Thread.current[:content_hook_calls] = 0
  end

  teardown do
    Thread.current[:content_hook_calls] = nil
  end

  def test_hook_not_called_when_an_earlier_check_already_trapped
    post :create, params: { trap_field: 'spam' }
    assert_response :ok
    assert_empty response.body
    assert_equal 0, Thread.current[:content_hook_calls]
  end

  def test_hook_called_once_when_nothing_earlier_traps
    post :create, params: { trap_field: '' }
    assert_response :ok
    assert_equal 'success', response.body
    assert_equal 1, Thread.current[:content_hook_calls]
  end
end

# js_proof without nonce or mutation: the timestamp is unsigned, so only its age bounds the token.
class JsProofOnlyController < ActionController::Base
  spamtrap :trap_field, js_proof: true, only: :create
  def create; render plain: 'ok'; end
end

class JsProofExpiryTest < ActionController::TestCase
  tests JsProofOnlyController

  def test_fresh_js_token_passes
    at = Time.now.to_i - 5
    post :create, params: { trap_field: '', spamtrap_timestamp: at }.merge(spamtrap_js_param(honeypot: 'trap_field', at: at))
    assert_response :ok
    assert_equal 'ok', response.body
  end

  def test_js_token_older_than_nonce_timeout_is_rejected
    old = Time.now.to_i - Spamtrap.nonce_timeout - 10
    post :create, params: { trap_field: '', spamtrap_timestamp: old }.merge(spamtrap_js_param(honeypot: 'trap_field', at: old))
    assert_response :ok
    assert_empty response.body
  end
end

# Strict mutation plus JS proof: spamtrap_js must be on the framework allowlist or it traps as plaintext first.
class StrictJsProofController < ActionController::Base
  spamtrap :trap_field, mutate: :strict, nonce: true, js_proof: true, only: :create
  def create; render plain: 'ok'; end
end

class StrictJsProofControllerTest < ActionController::TestCase
  tests StrictJsProofController

  setup do
    @reasons = []
    Spamtrap.on_trap = ->(reason:) { @reasons << reason }
  end
  teardown { Spamtrap.on_trap = nil }

  def test_full_gauntlet_passes_and_missing_js_reports_no_js_not_plaintext
    at = Time.now.to_i - 5
    base = spamtrap_params(honeypot: 'trap_field', nonce: true, mutate: true, js_proof: true, at: at)
                 .merge(comment: { spamtrap_token('body', at) => 'hi' })
    post :create, params: base
    assert_equal 'ok', response.body

    post :create, params: base.merge(spamtrap_js: '')
    assert_empty response.body
    assert_equal [:no_js], @reasons
  end
end

# Spamtrap.token_context: opt-in binding of every token to a value derived from the request
# (e.g. host), so a token minted on one hostname doesn't verify on another.
class TokenContextNonceControllerTest < ActionController::TestCase
  tests NonceController

  setup do
    Spamtrap.token_context = ->(request) { request.host }
    @reasons = []
    Spamtrap.on_trap = ->(reason:) { @reasons << reason }
  end

  teardown do
    Spamtrap.token_context = nil
    Spamtrap.on_trap = nil
  end

  def test_nonce_minted_for_the_request_host_passes_on_that_host
    timestamp = Time.now.to_i
    @request.host = 'a.example'
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp, context: 'a.example')
    )
    assert_response :ok
    assert_equal 'success', response.body
    assert_empty @reasons
  end

  def test_nonce_minted_for_a_different_host_is_rejected
    timestamp = Time.now.to_i
    @request.host = 'b.example'
    post :create, params: { trap_field: '' }.merge(
      spamtrap_nonce_params(honeypot: 'trap_field', ip: '0.0.0.0', at: timestamp, context: 'a.example')
    )
    assert_response :ok
    assert_empty response.body
    assert_equal [:nonce_invalid], @reasons
  end
end

class TokenContextMutationControllerTest < ActionController::TestCase
  tests StrictMutationController

  setup do
    Spamtrap.token_context = ->(request) { request.host }
    @reasons = []
    Spamtrap.on_trap = ->(reason:) { @reasons << reason }
  end

  teardown do
    Spamtrap.token_context = nil
    Spamtrap.on_trap = nil
  end

  def test_mutation_token_minted_for_the_request_host_remaps_on_that_host
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp, context: 'a.example')
    @request.host = 'a.example'

    post :create, params: { trap_field: '', spamtrap_timestamp: timestamp, comment: { body_token => 'Hello' } }

    assert_response :ok
    assert_equal 'body', response.body
    assert_empty @reasons
  end

  def test_mutation_token_minted_for_a_different_host_is_rejected_as_plaintext
    timestamp  = Time.now.to_i
    body_token = spamtrap_token('body', timestamp, context: 'a.example')
    @request.host = 'b.example'

    post :create, params: { trap_field: '', spamtrap_timestamp: timestamp, comment: { body_token => 'Hello' } }

    assert_response :ok
    assert_empty response.body
    assert_equal [:plaintext_field], @reasons
  end
end

class TokenContextJsProofControllerTest < ActionController::TestCase
  tests JsProofOnlyController

  setup do
    Spamtrap.token_context = ->(request) { request.host }
    @reasons = []
    Spamtrap.on_trap = ->(reason:) { @reasons << reason }
  end

  teardown do
    Spamtrap.token_context = nil
    Spamtrap.on_trap = nil
  end

  def test_js_proof_minted_for_the_request_host_passes_on_that_host
    at = Time.now.to_i - 5
    @request.host = 'a.example'
    post :create, params: { trap_field: '', spamtrap_timestamp: at }.merge(
      spamtrap_js_param(honeypot: 'trap_field', at: at, context: 'a.example')
    )
    assert_response :ok
    assert_equal 'ok', response.body
    assert_empty @reasons
  end

  def test_js_proof_minted_for_a_different_host_is_rejected
    at = Time.now.to_i - 5
    @request.host = 'b.example'
    post :create, params: { trap_field: '', spamtrap_timestamp: at }.merge(
      spamtrap_js_param(honeypot: 'trap_field', at: at, context: 'a.example')
    )
    assert_response :ok
    assert_empty response.body
    assert_equal [:no_js], @reasons
  end
end

# With Spamtrap.token_context unset (the default), context is nil throughout, so a token
# minted with no context must behave exactly as before this feature existed.
class TokenContextUnsetTest < Minitest::Test
  def test_nonce_digest_with_nil_context_matches_the_pre_token_context_message_format
    timestamp = Time.now.to_i
    key = Spamtrap::Crypto.keys_for(Spamtrap.secret_key_base)[:nonce]
    expected = OpenSSL::HMAC.hexdigest('SHA256', key, "v1:#{timestamp}:0.0.0.0:trap_field:#{'a' * 32}")

    actual = Spamtrap::TestHelper::TokenHelper.new.spamtrap_nonce_digest(timestamp, '0.0.0.0', 'trap_field', 'a' * 32)

    assert_equal expected, actual
  end
end
