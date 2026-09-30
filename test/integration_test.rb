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

  def test_logged_params_mask_mutated_fields_the_app_filters
    form = rendered_form
    name_of = ->(id) { response.body[/<input[^>]*id="#{id}"[^>]*>/][/name="comment\[([^\]]*)\]"/, 1] }
    email, body = name_of.('comment_email'), name_of.('comment_body')

    post '/integration/create', params: form
    assert_response :ok
    logged = request.filtered_parameters['comment']
    assert_equal ActiveSupport::ParameterFilter::FILTERED, logged[email]
    assert_equal 'x', logged[body]
  end
end

# Spamtrap.token_context bound to the request host: rendering and posting on the same
# hostname works as before; posting the rendered form after the host changes is rejected.
class TokenContextIntegrationTest < ActionDispatch::IntegrationTest
  setup do
    Rails.cache.clear
    Spamtrap.token_context = ->(request) { request.host }
    @reasons = []
    Spamtrap.on_trap = ->(reason:) { @reasons << reason }
  end

  teardown do
    Spamtrap.on_trap = nil
    Spamtrap.token_context = nil
    Spamtrap.min_fill_time = false # the suite-wide baseline set in test_helper
  end

  def rendered_form
    get '/integration/new'
    assert_response :ok
    fields = response.body.scan(/<input[^>]*>/).to_h { |t| [t[/name="([^"]*)"/, 1], t[/value="([^"]*)"/, 1] || 'x'] }
    honeypot_name = response.body[/<textarea[^>]*name="([^"]*)"/, 1]
    fields.compact.merge(honeypot_name => '')
  end

  def test_same_host_render_and_submit_passes
    host! 'a.example'
    form = rendered_form

    post '/integration/create', params: form
    assert_response :ok
    assert_equal %w[body email], JSON.parse(response.body).keys.sort
    assert_empty @reasons
  end

  def test_posting_the_rendered_form_after_the_host_changes_is_rejected
    host! 'a.example'
    form = rendered_form

    host! 'b.example'
    post '/integration/create', params: form
    assert_response :unprocessable_entity
    # IntegrationController mutates strictly, so a field that no longer decrypts is caught
    # by the mutation check before the (also-failing) nonce check ever runs.
    assert_equal [:plaintext_field], @reasons
  end
end

class IntegrationJsController < ActionController::Base
  spamtrap :trap_field, mutate: true, nonce: true, js_proof: true, only: :create,
           trap_response: :unprocessable,
           suspicious_if: ->(params) { params[:comment][:body].to_s.include?('http') }

  def new
    render inline: <<~ERB
      <%= form_with scope: :comment, url: '/integration_js/create', spamtrap: { mutate: true, nonce: true, js_proof: true } do |f| %>
        <%= f.text_field :body %>
        <%= f.spamtrap :trap_field, styles: %i[textarea text checkbox] %>
      <% end %>
    ERB
  end

  def create
    render plain: params[:comment].to_unsafe_h.to_json
  end
end

class IntegrationJsTest < ActionDispatch::IntegrationTest
  setup do
    Rails.cache.clear
    @reasons = []
    Spamtrap.on_trap = ->(reason:) { @reasons << reason }
  end

  teardown { Spamtrap.on_trap = nil }

  # What a browser would submit: every field, with the JS token filled in the way the
  # inline script does (reverse the embedded literal), keyed by rendered name.
  def rendered_form
    get '/integration_js/new'
    assert_response :ok
    html = response.body
    fields = html.scan(/<input[^>]*>/).to_h { |t| [t[/name="([^"]*)"/, 1], t[/value="([^"]*)"/, 1] || ''] }.compact
    @decoys = { textarea: html[/<textarea[^>]*name="([^"]*)"/, 1] }
    decoy_inputs = fields.keys.reject { |k| k.start_with?('comment[', 'spamtrap_', 'authenticity') }
    @decoys[:text] = decoy_inputs.find { |k| html.include?(%(type="text" name="#{k}")) }
    @decoys[:checkbox] = decoy_inputs.find { |k| html.include?(%(type="checkbox" name="#{k}")) }
    reversed = html[/value="([^"]+)"\.split\(""\)\.reverse\(\)\.join\(""\)/, 1]
    fields['spamtrap_js'] = reversed.reverse
    fields.delete(@decoys[:checkbox]) # unchecked boxes are not submitted
    fields.merge(@decoys[:textarea] => '')
  end

  def test_browser_like_submission_passes_and_script_carries_no_plain_digest
    form = rendered_form
    assert_includes response.body, '<script'
    refute_includes response.body, form['spamtrap_js'] # only the reversed literal is in the page
    post '/integration_js/create', params: form.merge('comment' => { form.keys.grep(/comment/).first[/\[(.+)\]/, 1] => 'hello' })
    assert_response :ok
    assert_equal({ 'body' => 'hello' }, JSON.parse(response.body))
    assert_empty @reasons
  end

  def test_submission_without_running_the_script_is_rejected
    form = rendered_form
    form['spamtrap_js'] = ''
    post '/integration_js/create', params: form
    assert_response :unprocessable_entity
    assert_equal [:no_js], @reasons
  end

  def test_each_decoy_style_traps_when_filled
    form = rendered_form
    refute_nil @decoys[:text]
    refute_nil @decoys[:checkbox]
    post '/integration_js/create', params: form.merge(@decoys[:text] => 'bot')
    assert_response :unprocessable_entity
    post '/integration_js/create', params: rendered_form.merge(@decoys[:checkbox] => '1')
    assert_response :unprocessable_entity
    assert_equal [:honeypot, :honeypot], @reasons
  end

  def test_content_hook_traps_a_link_after_every_other_check_passes
    form = rendered_form
    token = form.keys.grep(/comment/).first[/\[(.+)\]/, 1]
    post '/integration_js/create', params: form.merge('comment' => { token => 'visit http://spam.example' })
    assert_response :unprocessable_entity
    assert_equal [:content], @reasons
  end
end
