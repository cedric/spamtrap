require File.join(File.dirname(__FILE__), 'test_helper')
require 'action_view'
require 'action_view/test_case'

# A simple model-like struct to back the form builder, mimicking an AR model.
Message = Struct.new(:name, :email, :body, :active, :country)

class FormBuilderMutationTest < ActionView::TestCase
  include Spamtrap::Crypto

  # Build a minimal form builder instance backed by a Message object.
  def build_form_builder(object)
    ActionView::Helpers::FormBuilder.new(:message, object, self, {})
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

    assert_match 'Alice', f.text_field(:name)
    assert_match 'alice@example.com', f.email_field(:email)
    assert_match 'Hello', f.text_area(:body)
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

    assert_match 'Overridden', html
    refute_match 'Alice', html
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

    assert_match 'checked', f.check_box(:active)
  end

  def test_check_box_unchecked_when_model_value_is_false
    msg = Message.new(nil, nil, nil, false)
    f   = build_form_builder(msg)
    f.spamtrap(:trap, mutate: true)

    refute_match 'checked', f.check_box(:active)
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

  private

  # ActionView::TestCase helpers expect a #request method; provide a stub.
  def request
    @request ||= ActionDispatch::TestRequest.create
  end
end
