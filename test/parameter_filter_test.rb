require File.join(File.dirname(__FILE__), 'test_helper')

class ParameterFilterTest < ActiveSupport::TestCase
  include Spamtrap::TestHelper

  FILTERED = ActiveSupport::ParameterFilter::FILTERED

  setup do
    @original_filters = Rails.application.config.filter_parameters
    @at = Time.now.to_i
  end

  teardown do
    Rails.application.config.filter_parameters = @original_filters
    Spamtrap.filter_parameters = nil
    Spamtrap.secret_key_base = nil
    Spamtrap.previous_secret_key_base = nil
  end

  def filter(params)
    ActiveSupport::ParameterFilter.new(Rails.application.config.filter_parameters).filter(params)
  end

  def token(name, context: nil)
    spamtrap_token(name, @at, context: context)
  end

  def form(fields)
    { 'spamtrap_timestamp' => @at.to_s, 'comment' => fields }
  end

  def test_the_railtie_appends_the_block_to_the_apps_filters
    assert_includes Rails.application.config.filter_parameters, Spamtrap::ParameterFilter::BLOCK
  end

  def test_a_mutated_field_the_app_filters_is_masked_and_others_are_kept
    email, body = token(:email), token(:body)
    filtered = filter(form(email => 'jane@example.com', body => 'Hello'))['comment']

    assert_equal FILTERED, filtered[email]
    assert_equal 'Hello', filtered[body]
  end

  def test_the_apps_own_filters_decide_including_regexps_added_later
    phone = token(:phone)
    assert_equal '555', filter(form(phone => '555'))['comment'][phone]

    Rails.application.config.filter_parameters += [/\Aphone\z/]
    assert_equal FILTERED, filter(form(phone => '555'))['comment'][phone]
  end

  # Rails 7.1+ replaces the list in place with precompiled filters on first use; blocks survive.
  def test_works_against_a_precompiled_filter_list
    Rails.application.config.filter_parameters =
      ActiveSupport::ParameterFilter.precompile_filters(Rails.application.config.filter_parameters)
    email = token(:email)
    assert_equal FILTERED, filter(form(email => 'jane@example.com'))['comment'][email]
  end

  def test_dotted_filters_match_the_real_path
    Rails.application.config.filter_parameters += ['credit_card.number']
    card, ticket = token(:number), token(:number)
    params = { 'spamtrap_timestamp' => @at.to_s, 'credit_card' => { card => '4111' }, 'ticket' => { ticket => '12' } }
    filtered = filter(params)

    assert_equal FILTERED, filtered['credit_card'][card]
    assert_equal '12', filtered['ticket'][ticket]
  end

  # A block can't tell which occurrence it's filtering, so a shared token masks everywhere.
  def test_a_token_shared_across_parents_is_masked_if_any_path_matches
    Rails.application.config.filter_parameters += ['credit_card.number']
    number = token(:number)
    params = { 'spamtrap_timestamp' => @at.to_s, 'credit_card' => { number => '4111' }, 'ticket' => { number => '12' } }

    assert_equal FILTERED, filter(params)['ticket'][number]
  end

  # Rails leaves array positions out of the dotted path, so order.cards.number covers every card.
  def test_dotted_filters_see_through_arrays_of_nested_objects
    Rails.application.config.filter_parameters += ['order.cards.number']
    number = token(:number)
    params = { 'spamtrap_timestamp' => @at.to_s, 'order' => { 'cards' => [{ number => '4111' }, { number => '5500' }] } }

    assert_equal [FILTERED, FILTERED], filter(params)['order']['cards'].map { |card| card[number] }
  end

  def test_masks_tokens_bound_to_a_token_context_it_cannot_compute
    email = token(:email, context: 'site-3')
    assert_equal FILTERED, filter(form(email => 'jane@example.com'))['comment'][email]
  end

  def test_masks_tokens_minted_under_the_previous_secret
    Spamtrap.secret_key_base = 'b' * 64
    email = token(:email)
    Spamtrap.previous_secret_key_base = 'b' * 64
    Spamtrap.secret_key_base = 'c' * 64

    assert_equal FILTERED, filter(form(email => 'jane@example.com'))['comment'][email]
  end

  def test_masks_top_level_array_and_date_select_values
    email = token(:email)
    params = {
      'spamtrap_timestamp' => @at.to_s,
      email => ['a@example.com', 'b@example.com'],
      "#{token(:email_on)}(1i)" => '2026'
    }
    filtered = filter(params)

    assert_equal [FILTERED, FILTERED], filtered[email]
    assert_equal FILTERED, filtered.values.last
  end

  def test_leaves_values_alone_on_requests_without_a_spamtrap_timestamp
    email = token(:email)
    assert_equal 'jane@example.com', filter('comment' => { email => 'jane@example.com' })['comment'][email]
  end

  def test_leaves_values_alone_when_switched_off
    Spamtrap.filter_parameters = false
    email = token(:email)
    assert_equal 'jane@example.com', filter(form(email => 'jane@example.com'))['comment'][email]
  end

  # /\A[A-F]/ matches about one token in eleven, so 200 with none is the redraw at work: without
  # it, all 200 missing is a three-in-a-billion chance.
  def test_redraws_a_token_the_apps_filters_would_match_as_it_stands
    Rails.application.config.filter_parameters += [/\A[A-F]/]
    tokens = Array.new(200) { token(:body) }

    assert tokens.none? { |t| t.match?(/\A[A-F]/) }
    assert_equal :body, spamtrap_decrypt(tokens.first, @at)
  end

  def test_stops_redrawing_when_every_token_would_match
    Rails.application.config.filter_parameters += [/./]
    assert_equal :body, spamtrap_decrypt(token(:body), @at)
  end

  def test_does_not_redraw_when_switched_off
    Spamtrap.filter_parameters = false
    Rails.application.config.filter_parameters += [/\A[A-F]/]
    assert Array.new(200) { token(:body) }.any? { |t| t.match?(/\A[A-F]/) }
  end

  def test_ignores_keys_that_only_look_like_tokens
    params = form('A' * 40 => 'x', 'B' * 41 => 'y', 'a_long_plaintext_parameter_name_of_forty_chars' => 'z')
    assert_equal({ 'A' * 40 => 'x', 'B' * 41 => 'y', 'a_long_plaintext_parameter_name_of_forty_chars' => 'z' }, filter(params)['comment'])
  end
end
