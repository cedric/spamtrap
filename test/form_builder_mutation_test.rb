# frozen_string_literal: true

require File.join(File.dirname(__FILE__), 'test_helper')
require 'action_view'
require 'action_view/test_case'
require 'active_model'

# A simple id/name pair, for collection_check_boxes/collection_radio_buttons tests.
Author = Struct.new(:id, :name)

# A simple model-like struct to back the form builder, mimicking an AR model.
Message = Struct.new(
  :name, :email, :body, :active, :country,
  :phone, :born_at, :category, :author_ids, :author_id,
  :zone, :weekday, :meeting_at, :meeting_date, :meeting_time, :content
)

# A model with real ActiveModel errors, for field_with_errors wrapping tests.
class ErroredMessage
  include ActiveModel::Model
  attr_accessor :name
end

class FormBuilderMutationTest < ActionView::TestCase
  include Spamtrap::Crypto

  teardown do
    Spamtrap.stable_ids = nil
  end

  # Build a minimal form builder instance backed by a Message object.
  def build_form_builder(object)
    ActionView::Helpers::FormBuilder.new(:message, object, self, {})
  end

  # Build a Message with only the given attributes set, by name, so tests don't
  # have to count positional Struct.new arguments.
  def build_message(**attrs)
    msg = Message.new
    attrs.each { |k, v| msg[k] = v }
    msg
  end

  # --- text-like inputs ---

  def test_text_field_does_not_raise_when_mutate_is_true
    msg = Message.new('Alice', 'alice@example.com', 'Hello')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    assert_nothing_raised { f.text_field(:name) }
    assert_nothing_raised { f.email_field(:email) }
    assert_nothing_raised { f.text_area(:body) }
  end

  def test_model_value_is_preserved_in_encrypted_field
    msg = Message.new('Alice', 'alice@example.com', 'Hello')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    assert_includes f.text_field(:name), 'Alice'
    assert_includes f.email_field(:email), 'alice@example.com'
    assert_includes f.text_area(:body), 'Hello'
  end

  def test_encrypted_field_name_is_used_in_html
    msg = Message.new('Alice', 'alice@example.com', 'Hello')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.text_field(:name)

    # The original unencrypted name must NOT appear as the input name attribute
    refute_match(/name="message\[name\]"/, html)
  end

  def test_nil_model_value_does_not_raise
    msg = Message.new(nil, nil, nil)
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    assert_nothing_raised { f.text_field(:name) }
  end

  def test_virtual_field_without_model_method_does_not_raise
    msg = Message.new('Alice', 'alice@example.com', 'Hello')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    # :nonexistent is not a method on Message; should render with empty value, not crash
    assert_nothing_raised { f.text_field(:nonexistent) }
  end

  def test_explicit_value_option_is_preserved
    msg = Message.new('Alice', 'alice@example.com', 'Hello')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.text_field(:name, value: 'Overridden')

    assert_includes html, 'Overridden'
    refute_includes html, 'Alice'
  end

  # --- no mutation ---

  def test_no_salt_leaves_field_names_unencrypted
    msg = Message.new('Alice', 'alice@example.com', 'Hello')
    f   = build_form_builder(msg)

    html = f.text_field(:name)

    assert_match(/name="message\[name\]"/, html)
  end

  # --- check_box ---

  def test_check_box_does_not_raise_when_mutate_is_true
    msg = Message.new(nil, nil, nil, true)
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    assert_nothing_raised { f.check_box(:active) }
  end

  def test_check_box_checked_when_model_value_is_true
    msg = Message.new(nil, nil, nil, true)
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    assert_includes f.check_box(:active), 'checked'
  end

  def test_check_box_unchecked_when_model_value_is_false
    msg = Message.new(nil, nil, nil, false)
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    refute_includes f.check_box(:active), 'checked'
  end

  # --- select ---

  def test_select_does_not_raise_when_mutate_is_true
    msg = Message.new(nil, nil, nil, nil, 'US')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    assert_nothing_raised { f.select(:country, %w[US CA GB]) }
  end

  def test_select_preselects_model_value
    msg = Message.new(nil, nil, nil, nil, 'CA')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.select(:country, %w[US CA GB])

    assert_match(/selected.*CA|CA.*selected/, html)
  end

  # --- label ---

  def test_label_does_not_raise_when_mutate_is_true
    msg = Message.new('Alice', 'alice@example.com', 'Hello')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    assert_nothing_raised { f.label(:name) }
  end

  def test_label_with_explicit_nil_text_does_not_raise
    # Regression: a subclass that calls super(method, nil, options) used to
    # produce "wrong number of arguments (given 4, expected 1..3)" because the
    # nil survived as a positional argument alongside the auto-generated text.
    msg  = Message.new('Alice', 'alice@example.com', 'Hello')
    base = build_form_builder(msg)
    base.spamtrap(:trap, mutate: true)

    # Simulate what a subclass does: call label with nil text explicitly.
    assert_nothing_raised { base.label(:name, nil, class: 'my-label') }
  end

  def test_label_with_explicit_nil_text_uses_humanized_fallback
    msg  = Message.new('Alice', 'alice@example.com', 'Hello')
    base = build_form_builder(msg)
    base.spamtrap(:trap, mutate: true)

    html = base.label(:name, nil, class: 'my-label')

    assert_includes html, 'Name'
  end

  # --- per-field IV ---

  def test_distinct_fields_get_distinct_ivs
    msg = Message.new('Alice', 'alice@example.com', 'Hello')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    name_token  = f.text_field(:name)[/name="message\[([^\]]+)\]"/, 1]
    email_token = f.email_field(:email)[/name="message\[([^\]]+)\]"/, 1]
    timestamp   = f.instance_variable_get(:@spamtrap_timestamp)

    refute_equal name_token[0, 16], email_token[0, 16]
    assert_equal :name,  spamtrap_decrypt(name_token,  timestamp)
    assert_equal :email, spamtrap_decrypt(email_token, timestamp)
  end

  def test_label_and_field_share_the_same_token
    msg = Message.new('Alice', 'alice@example.com', 'Hello')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    label_for = f.label(:body)[/for="([^"]+)"/, 1]
    field_id  = f.text_field(:body)[/id="([^"]+)"/, 1]

    assert_equal field_id, label_for
  end

  def test_spamtrap_emits_timestamp_once_when_mutate_and_nonce_are_both_enabled
    msg = Message.new('Alice', 'alice@example.com', 'Hello')
    f   = build_form_builder(msg)

    html = f.spamtrap(:x, mutate: true, nonce: true)

    assert_equal 1, html.scan('name="spamtrap_timestamp"').size
    assert_equal 1, html.scan('name="spamtrap_nonce_id"').size
    assert_equal 1, html.scan('name="spamtrap_nonce"').size
    refute_includes html, 'spamtrap_mutation_salt'
  end

  # --- honeypot defaults (task 1) ---

  def test_spamtrap_honeypot_has_autofill_and_accessibility_safe_defaults
    msg  = Message.new
    f    = build_form_builder(msg)
    html = f.spamtrap(:trap)

    assert_match(/tabindex="-1"/, html)
    assert_match(/autocomplete="off"/, html)
    assert_match(/aria-hidden="true"/, html)
    assert_match(/style="display:none"/, html)
    assert_match(/class="spamtrap"/, html)
  end

  def test_spamtrap_honeypot_style_nil_drops_inline_style_but_keeps_other_defaults
    msg  = Message.new
    f    = build_form_builder(msg)
    html = f.spamtrap(:trap, style: nil)

    refute_match(/style=/, html)
    assert_match(/tabindex="-1"/, html)
    assert_match(/autocomplete="off"/, html)
    assert_match(/aria-hidden="true"/, html)
  end

  # --- honeypot name mutation ---

  def test_honeypot_name_is_encrypted_when_mutate_is_true
    msg  = Message.new
    f    = build_form_builder(msg)
    html = f.spamtrap(:trap, mutate: true)

    name      = html[/<textarea[^>]*\sname="([^"]+)"/, 1]
    timestamp = f.instance_variable_get(:@spamtrap_timestamp)

    refute_equal 'trap', name
    assert_equal :trap, spamtrap_decrypt(name, timestamp)
  end

  def test_honeypot_name_stays_plain_when_mutate_is_false
    msg  = Message.new
    f    = build_form_builder(msg)
    html = f.spamtrap(:trap, mutate: false)

    assert_match(/<textarea[^>]*\sname="trap"/, html)
  end

  def test_honeypot_name_stays_plain_without_mutation_option
    msg  = Message.new
    f    = build_form_builder(msg)
    html = f.spamtrap(:trap)

    assert_match(/<textarea[^>]*\sname="trap"/, html)
  end

  def test_honeypot_hidden_fields_keep_plain_names_when_mutate_is_true
    msg  = Message.new
    f    = build_form_builder(msg)
    html = f.spamtrap(:trap, mutate: true)

    assert_match(/name="spamtrap_timestamp"/, html)
  end

  def test_honeypot_hidden_nonce_fields_keep_plain_names_when_mutate_and_nonce_are_true
    msg  = Message.new
    f    = build_form_builder(msg)
    html = f.spamtrap(:trap, mutate: true, nonce: true)

    assert_match(/name="spamtrap_timestamp"/, html)
    assert_match(/name="spamtrap_nonce_id"/, html)
    assert_match(/name="spamtrap_nonce"/, html)
  end

  # --- spamtrap: options at builder construction (task 2) ---

  def test_form_with_spamtrap_option_mutates_fields_rendered_before_f_spamtrap
    html = form_with(scope: :message, url: '/x', spamtrap: { mutate: true }) do |f|
      f.text_field(:name) + f.spamtrap(:trap)
    end

    refute_match(/name="message\[name\]"/, html)
    assert_equal 1, html.scan('name="spamtrap_timestamp"').size
    refute_match(/<form[^>]*\sspamtrap="/, html)
  end

  def test_form_for_spamtrap_option_mutates_fields_rendered_before_f_spamtrap
    html = form_for(:message, url: '/x', spamtrap: { mutate: true }) do |f|
      f.text_field(:name) + f.spamtrap(:trap)
    end

    refute_match(/name="message\[name\]"/, html)
    assert_equal 1, html.scan('name="spamtrap_timestamp"').size
    refute_match(/<form[^>]*\sspamtrap="/, html)
  end

  # --- request-less rendering guard (task 3) ---

  def test_spamtrap_nonce_fields_without_a_request_raises_no_request_error
    msg = Message.new
    f   = build_form_builder(msg)

    original_request = request
    self.request = nil

    error = assert_raises(Spamtrap::NoRequestError) { f.spamtrap(:trap, nonce: true) }
    assert_match(/render the form inside a request/, error.message)
  ensure
    self.request = original_request
  end

  # --- radio_button (task 4) ---

  def test_radio_button_checked_reflects_model_value_and_name_is_encrypted
    msg = build_message(category: 'rails')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    checked_html   = f.radio_button(:category, 'rails')
    unchecked_html = f.radio_button(:category, 'java')

    refute_match(/name="message\[category\]"/, checked_html)
    assert_match(/checked="checked"/, checked_html)
    refute_match(/checked/, unchecked_html)
  end

  # --- phone_field / datetime_field (task 4) ---

  def test_phone_field_value_reflects_model_and_name_is_encrypted
    msg  = build_message(phone: '555-1234')
    f    = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.phone_field(:phone)

    assert_includes html, '555-1234'
    refute_match(/name="message\[phone\]"/, html)
  end

  def test_datetime_field_value_reflects_model_and_name_is_encrypted
    msg  = build_message(born_at: Time.utc(2020, 1, 2, 3, 4))
    f    = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.datetime_field(:born_at)

    assert_includes html, '2020-01-02T03:04'
    refute_match(/name="message\[born_at\]"/, html)
  end

  # --- time_zone_select / weekday_select (task 4) ---

  def test_time_zone_select_selected_reflects_model_and_name_is_encrypted
    msg  = build_message(zone: 'Eastern Time (US & Canada)')
    f    = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.time_zone_select(:zone)

    refute_match(/name="message\[zone\]"/, html)
    assert_match(/selected="selected"/, html)
    assert_includes html, 'Eastern Time'
  end

  def test_weekday_select_selected_reflects_model_and_name_is_encrypted
    msg  = build_message(weekday: 'Monday')
    f    = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.weekday_select(:weekday)

    refute_match(/name="message\[weekday\]"/, html)
    assert_match(/selected="selected"/, html)
    assert_includes html, 'Monday'
  end

  # --- collection_check_boxes / collection_radio_buttons (task 4) ---

  def test_collection_check_boxes_checked_reflects_model_and_name_is_encrypted
    msg     = build_message(author_ids: [2])
    f       = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)
    authors = [Author.new(1, 'Alice'), Author.new(2, 'Bob')]

    html = f.collection_check_boxes(:author_ids, authors, :id, :name)

    refute_match(/name="message\[author_ids\]/, html)
    assert_match(/value="2"[^>]*checked="checked"/, html)
    refute_match(/value="1"[^>]*checked="checked"/, html)
  end

  def test_collection_radio_buttons_checked_reflects_model_and_name_is_encrypted
    msg     = build_message(author_id: 2)
    f       = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)
    authors = [Author.new(1, 'Alice'), Author.new(2, 'Bob')]

    html = f.collection_radio_buttons(:author_id, authors, :id, :name)

    refute_match(/name="message\[author_id\]/, html)
    assert_match(/value="2"[^>]*checked="checked"/, html)
    refute_match(/value="1"[^>]*checked="checked"/, html)
  end

  # --- date_select / time_select / datetime_select (task 4) ---

  # Every rendered <select> name must be an encrypted base token plus Rails' own
  # multiparameter suffix (e.g. "(1i)"), and the base token must decrypt back to
  # the real field name.
  def assert_multiparameter_names_decrypt_to(html, field, timestamp)
    names = html.scan(/name="([^"]+)"/).flatten
    refute_empty names
    names.each do |name|
      assert_match(/\Amessage\[[A-Za-z0-9_-]+\(\d[a-z]\)\]\z/, name)
      token = name[/\Amessage\[([A-Za-z0-9_-]+)\(\d[a-z]\)\]\z/, 1]
      assert_equal field, spamtrap_decrypt(token, timestamp)
    end
  end

  def test_date_select_names_are_encrypted_multiparameter_fields
    msg = build_message(meeting_date: Date.new(2020, 1, 2))
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.date_select(:meeting_date)
    assert_multiparameter_names_decrypt_to(html, :meeting_date, f.instance_variable_get(:@spamtrap_timestamp))
  end

  def test_time_select_names_are_encrypted_multiparameter_fields
    msg = build_message(meeting_time: Time.utc(2020, 1, 2, 3, 4))
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.time_select(:meeting_time)
    assert_multiparameter_names_decrypt_to(html, :meeting_time, f.instance_variable_get(:@spamtrap_timestamp))
  end

  def test_datetime_select_names_are_encrypted_multiparameter_fields
    msg = build_message(meeting_at: Time.utc(2020, 1, 2, 3, 4))
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.datetime_select(:meeting_at)
    assert_multiparameter_names_decrypt_to(html, :meeting_at, f.instance_variable_get(:@spamtrap_timestamp))
  end

  # --- rich_text_area (task 4) ---

  def test_rich_text_area_raises_clear_error_when_action_text_is_not_loaded
    msg = build_message(content: 'hello')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    error = assert_raises(NoMethodError) { f.rich_text_area(:content) }
    assert_match(/rich_text_area/, error.message)
  end

  # --- stable ids (task 5) ---

  def test_stable_ids_on_text_field_id_is_derived_from_real_field_name
    msg = build_message(name: 'Alice')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.text_field(:name)

    assert_match(/id="message_name"/, html)
    refute_match(/name="message\[name\]"/, html)
  end

  def test_stable_ids_on_label_for_matches_the_real_field_id
    msg = build_message(name: 'Alice')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    assert_match(/for="message_name"/, f.label(:name))
  end

  def test_stable_ids_false_uses_the_opaque_encrypted_id
    Spamtrap.stable_ids = false
    msg = build_message(name: 'Alice')
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    html = f.text_field(:name)

    refute_match(/id="message_name"/, html)
  end

  # --- field_with_errors wrapping (task 5) ---

  def test_field_with_errors_wraps_mutated_text_field_and_label_exactly_once
    msg = ErroredMessage.new(name: 'Al')
    msg.errors.add(:name, 'is too short')

    f = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    field_html = f.text_field(:name)
    label_html = f.label(:name)

    assert_equal 1, field_html.scan('field_with_errors').size
    assert_equal 1, label_html.scan('field_with_errors').size
    assert_match(/\A<div class="field_with_errors">.*<\/div>\z/, field_html)
  end

  def test_field_without_errors_is_not_wrapped
    msg = ErroredMessage.new(name: 'Alice')

    f = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    refute_match(/field_with_errors/, f.text_field(:name))
  end


  def test_fields_for_children_share_one_token_per_field_name
    f = build_form_builder(Message.new('Alice'))
    f.spamtrap(:trap, mutate: true)
    names = 2.times.map do
      html = +''
      f.fields_for(:items) { |c| html << c.text_field(:name) }
      html[/name="([^"]*)"/, 1]
    end
    assert_equal 1, names.uniq.size, names.inspect
    assert_match(/\Amessage\[items\]\[[A-Za-z0-9_-]+\]\z/, names.first)
    assert_equal f.text_field(:name)[/name="message\[([^\]]+)\]"/, 1], names.first[/\]\[([^\]]+)\]\z/, 1]
  end

end
