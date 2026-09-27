require File.join(File.dirname(__FILE__), 'test_helper')

# Full render-and-submit path: the view helper mints the fields, a real request posts
# them back. Covers what the controller tests cannot: nonce fields produced by the helper,
# single-use replay, the encrypted honeypot, fill time, and the notification payload.
class IntegrationController < ActionController::Base
  spamtrap :trap_field, mutate: true, nonce: :single_use, only: :create,
           trap_response: { honeypot: :head, default: :unprocessable }

  def new
    render inline: <<~ERB
      <%= form_with scope: :comment, url: '/integration/create', spamtrap: { mutate: true, nonce: true } do |f| %>
        <%= f.label :body %><%= f.text_field :body %>
        <%= f.email_field :email %>
        <%= f.spamtrap :trap_field %>
        <%= f.submit 'Save' %>
      <% end %>
    ERB
  end

  def create
    render plain: params[:comment].to_unsafe_h.to_json
  end
end

class IntegrationTest < ActionDispatch::IntegrationTest
  setup do
    Rails.cache.clear
    @reasons = []
    Spamtrap.on_trap = ->(reason:) { @reasons << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
    Spamtrap.min_fill_time = false # the suite-wide baseline set in test_helper
  end

  # Every submittable field from the rendered form, keyed by name. The honeypot is a
  # textarea, so it is collected alongside the inputs.
  def rendered_form
    get '/integration/new'
    assert_response :ok
    fields = response.body.scan(/<input[^>]*>/).to_h { |t| [t[/name="([^"]*)"/, 1], t[/value="([^"]*)"/, 1] || 'x'] }
    @honeypot_name = response.body[/<textarea[^>]*name="([^"]*)"/, 1]
    fields.compact.merge(@honeypot_name => '')
  end

  def test_rendered_form_round_trips_with_real_names_stable_ids_and_encrypted_honeypot
    form = rendered_form
    assert_includes response.body, 'id="comment_body"'
    assert_includes response.body, 'for="comment_body"'
    assert_includes response.body, 'aria-hidden="true"'
    refute_includes response.body, 'name="trap_field"'
    refute_includes response.body, 'name="comment[body]"'

    post '/integration/create', params: form
    assert_response :ok
    assert_equal %w[body email], JSON.parse(response.body).keys.sort
    assert_empty @reasons
  end

  def test_replaying_the_same_form_is_rejected
    form = rendered_form
    post '/integration/create', params: form
    assert_response :ok

    post '/integration/create', params: form
    assert_response :unprocessable_entity
    assert_equal [:nonce_replayed], @reasons
  end

  def test_plaintext_field_name_is_rejected
    form = rendered_form.merge('comment' => { 'body' => 'spam' })
    post '/integration/create', params: form
    assert_response :unprocessable_entity
    assert_equal [:plaintext_field], @reasons
  end

  def test_filled_honeypot_is_discarded_silently
    form = rendered_form
    post '/integration/create', params: form.merge(@honeypot_name => 'bot text')
    assert_response :ok
    assert_empty response.body
    assert_equal [:honeypot], @reasons
  end

  def test_submitting_within_min_fill_time_is_rejected_and_passes_after_waiting
    Spamtrap.min_fill_time = 1
    form = rendered_form

    post '/integration/create', params: form
    assert_response :unprocessable_entity
    assert_equal [:too_fast], @reasons

    travel 2.seconds do
      post '/integration/create', params: form
      assert_response :ok
    end
  end

  def test_trap_publishes_a_notification
    events = []
    ActiveSupport::Notifications.subscribed(->(*, payload) { events << payload }, 'trap.spamtrap') do
      post '/integration/create', params: rendered_form.merge('comment' => { 'body' => 'spam' })
    end
    assert_equal 1, events.size
    assert_equal :plaintext_field, events.first[:reason]
    assert_equal 'integration', events.first[:controller]
    assert_equal 'create', events.first[:action]
    assert_equal 'trap_field', events.first[:honeypot]
  end
end
