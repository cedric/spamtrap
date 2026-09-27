module Spamtrap::Controller
  include Spamtrap::Crypto

  # Fields Rails/browsers/forms add that a strict action must not treat as attacker-controlled plaintext.
  FRAMEWORK_PARAMS = %w[
    authenticity_token commit button _method utf8
    spamtrap_timestamp spamtrap_nonce spamtrap_nonce_id
  ].freeze

  # Captcha widgets inject their own plaintext param the app can't encrypt: Google
  # reCAPTCHA v2/v3, hCaptcha, and Cloudflare Turnstile.
  CAPTCHA_PARAMS = %w[g-recaptcha-response h-captcha-response cf-turnstile-response].freeze

  def self.included(base)
    base.extend ActsAsMethods
  end

  module ActsAsMethods
    def spamtrap(honeypot = 'spamtrap', options = {}, &block)
      # Capture explicit per-call values; use sentinel so globals are read
      # at request time rather than at class definition time.
      nonce_opt         = options.key?(:nonce)         ? options.delete(:nonce)         : :global
      timeout_opt       = options.key?(:nonce_timeout) ? options.delete(:nonce_timeout) : :global
      mutate_opt        = options.key?(:mutate)        ? options.delete(:mutate)        : :global
      on_trap_opt       = options.key?(:on_trap)       ? options.delete(:on_trap)       : :global
      trap_response_opt = options.key?(:trap_response) ? options.delete(:trap_response) : :global
      nonce_bind_ip_opt = options.key?(:nonce_bind_ip) ? options.delete(:nonce_bind_ip) : :global
      min_fill_time_opt = options.key?(:min_fill_time) ? options.delete(:min_fill_time) : :global

      before_action(options) do |controller|
        next unless Spamtrap.enabled

        controller.instance_eval(&block) if block_given?
        controller.instance_eval do
          nonce_enabled    = nonce_opt         == :global ? Spamtrap.nonce         : nonce_opt
          nonce_timeout    = timeout_opt       == :global ? Spamtrap.nonce_timeout : timeout_opt
          mutate_enabled   = mutate_opt        == :global ? Spamtrap.mutate        : mutate_opt
          bind_ip          = nonce_bind_ip_opt == :global ? Spamtrap.nonce_bind_ip : nonce_bind_ip_opt
          min_fill_time    = min_fill_time_opt == :global ? Spamtrap.min_fill_time : min_fill_time_opt
          # true and :strict both trap plaintext keys; :lenient only remaps.
          strict           = mutate_enabled && mutate_enabled != :lenient

          remap = spamtrap_remap_params(Spamtrap.mutation_timeout) if mutate_enabled

          if params[honeypot].present?
            spamtrap_trap(:honeypot, honeypot, on_trap_opt, trap_response_opt)
          # :expired traps in lenient mode too, or a remapped-but-stale token would otherwise be accepted.
          elsif mutate_enabled && remap[0] == :expired
            spamtrap_trap(:mutation_expired, honeypot, on_trap_opt, trap_response_opt)
          elsif strict && (reason = spamtrap_strict_violation(remap, honeypot))
            spamtrap_trap(reason, honeypot, on_trap_opt, trap_response_opt)
          elsif nonce_enabled && (reason = spamtrap_nonce_failure(nonce_timeout, honeypot, nonce_enabled, bind_ip: bind_ip, min_fill_time: min_fill_time))
            spamtrap_trap(reason, honeypot, on_trap_opt, trap_response_opt)
          # Mutation-only forms: the nonce path above already applied the fill time.
          elsif !nonce_enabled && mutate_enabled && spamtrap_too_fast?(min_fill_time)
            spamtrap_trap(:too_fast, honeypot, on_trap_opt, trap_response_opt)
          end
        end
      end
    end
  end

  def spamtrap_nonce_failure(timeout, honeypot, mode, bind_ip: Spamtrap.nonce_bind_ip, min_fill_time: Spamtrap.min_fill_time)
    timestamp = params[:spamtrap_timestamp].to_i
    nonce     = params[:spamtrap_nonce].to_s
    nonce_id  = params[:spamtrap_nonce_id].to_s
    return :nonce_missing if timestamp.zero? || nonce.blank? || nonce_id.blank?

    now = Time.now.to_i
    # nonce_id doubles as a cache key under single-use mode, so bound its shape.
    return :nonce_invalid unless nonce_id.match?(/\A[0-9a-f]{32}\z/)
    return :nonce_invalid if timestamp - now > Spamtrap.nonce_skew
    return :nonce_expired if now - timestamp > timeout.to_i # checked before the HMAC so a genuine expired token reports as expired

    expected = spamtrap_nonce_digest(timestamp, request.remote_ip, honeypot, nonce_id, bind_ip: bind_ip)
    unless ActiveSupport::SecurityUtils.secure_compare(nonce, expected)
      # Retry with the previous secret during a rotation window before giving up.
      previous_secret = Spamtrap.previous_secret_key_base
      previous = previous_secret && spamtrap_nonce_digest(timestamp, request.remote_ip, honeypot, nonce_id, bind_ip: bind_ip, secret: previous_secret)
      return :nonce_invalid unless previous && ActiveSupport::SecurityUtils.secure_compare(nonce, previous)
    end

    # After the HMAC (so a forged timestamp is :nonce_invalid) but before single-use records
    # the id, or a human trapped as too fast could never resubmit the same page.
    return :too_fast if spamtrap_too_fast?(min_fill_time)

    if mode == :single_use
      key    = "spamtrap:nonce:#{nonce_id}"
      stored = Spamtrap.nonce_store.write(key, 1, unless_exist: true, expires_in: timeout.to_i + Spamtrap.nonce_skew)
      if Spamtrap.nonce_store.is_a?(ActiveSupport::Cache::NullStore)
        Spamtrap::Controller.warn_null_store_once
      elsif !stored
        return :nonce_replayed
      end
    end

    nil
  end

  # Warned once per process: a NullStore accepts every write, so it can never catch a replay.
  def self.warn_null_store_once
    return if @null_store_warned
    @null_store_warned = true
    Rails.logger.warn 'Spamtrap: nonce: :single_use needs a real Spamtrap.nonce_store; NullStore cannot detect replays.'
  end

  def spamtrap_too_fast?(min_fill_time)
    return false unless min_fill_time && min_fill_time.to_i.positive?

    ts = params[:spamtrap_timestamp].to_i
    ts.positive? && Time.now.to_i - ts < min_fill_time.to_i
  end

  # Returns [:missing, []], [:expired, leftovers], or [:ok, leftovers], where leftovers is
  # an array of [key, depth] for every submitted key that did not decrypt (depth 0 == top
  # level of params), letting spamtrap_strict_violation tell :missing apart from a real
  # plaintext violation. :expired still remaps every key (no additional staleness bound on
  # the decrypt itself) so on_trap/trap_response can re-render the form with the user's
  # input; the action never runs, so an old token can only help show that input back, and
  # key rotation bounds how far back it can reach.
  def spamtrap_remap_params(timeout)
    ts = params[:spamtrap_timestamp].to_i
    return [:missing, []] if ts.zero?

    now = Time.now.to_i
    status = now - ts > timeout.to_i || ts - now > Spamtrap.nonce_skew ? :expired : :ok
    [status, spamtrap_remap_hash(params, ts.to_s)]
  end

  def spamtrap_remap_hash(hash, aad, depth = 0)
    leftovers = []
    hash.each_key.to_a.each do |key|
      key_str = key.to_s
      # Rails date/time selects post <token>(1i)/(2i)/(3i); decrypt the base, keep the suffix.
      base, suffix = key_str.match(/\A(.+?)(\(\d+[a-z]\))\z/)&.captures
      real = spamtrap_decrypt_field(base || key_str, aad)
      if real
        renamed = suffix ? "#{real}#{suffix}" : real
        hash[renamed] = hash.delete(key)
        key = renamed
      end
      child = hash[key]
      # A nesting container (object name, or array of them) is structure, not a submitted
      # field name, so it's never itself flagged even when its own key didn't decrypt.
      container = child.is_a?(ActionController::Parameters) ||
                  (child.is_a?(Array) && child.any? { |el| el.is_a?(ActionController::Parameters) })
      leftovers << [key.to_s, depth] if real.nil? && !container
      case child
      when ActionController::Parameters
        leftovers.concat(spamtrap_remap_hash(child, aad, depth + 1))
      when Array
        child.each { |el| leftovers.concat(spamtrap_remap_hash(el, aad, depth + 1)) if el.is_a?(ActionController::Parameters) }
      end
    end
    leftovers
  end

  # nil means no violation. :mutation_expired means no timestamp was submitted at all, so
  # blaming a specific field with :plaintext_field would mislead (the :expired case is
  # already handled by the caller before this runs). Otherwise: any leftover below the top
  # level always traps (plaintext smuggled into an otherwise-encrypted nested object); a
  # top-level leftover only traps if it isn't allowlisted.
  def spamtrap_strict_violation(remap, honeypot)
    status, leftovers = remap
    return :mutation_expired if status == :missing
    return :plaintext_field if leftovers.any? { |_key, depth| depth > 0 }

    # controller/action/id/format are Rails' own routing params, always present and always plaintext.
    allowed = FRAMEWORK_PARAMS + CAPTCHA_PARAMS + [honeypot.to_s] + request.path_parameters.keys.map(&:to_s) + Spamtrap.allowed_params
    :plaintext_field if leftovers.any? { |key, _depth| !allowed.include?(key) }
  end

  # Logs, invokes on_trap, then applies the trap response unless the callback already
  # rendered/redirected (performed? short-circuits so a custom on_trap response wins).
  def spamtrap_trap(reason, honeypot, on_trap_opt, trap_response_opt)
    Rails.logger.warn "Spamtrap #{reason} from #{request.remote_ip}."
    payload = { reason: reason, honeypot: honeypot.to_s, controller: controller_path, action: action_name, ip: request.remote_ip, request: request }
    ActiveSupport::Notifications.instrument('trap.spamtrap', payload) { }
    spamtrap_invoke_on_trap(reason, on_trap_opt, honeypot)
    return if performed?

    setting = trap_response_opt == :global ? Spamtrap.trap_response : trap_response_opt
    spamtrap_render_trap(reason, setting)
  end

  # setting: a Hash keyed by reason (falls back to :default, then :head), a callable
  # (controller, reason), or one of :head/:no_content/:unprocessable/:redirect_back.
  def spamtrap_render_trap(reason, setting)
    if setting.is_a?(Hash)
      spamtrap_render_trap(reason, setting[reason] || setting[:default] || :head)
    elsif setting.respond_to?(:call)
      setting.call(self, reason)
      head 200 unless performed? # callable didn't render/redirect, so fall back
    elsif setting == :head
      head 200
    elsif setting == :no_content
      head 204
    elsif setting == :unprocessable
      head 422
    elsif setting == :redirect_back
      redirect_back_or_to('/', status: :see_other)
    else
      raise ArgumentError, "Unknown Spamtrap.trap_response: #{setting.inspect}"
    end
  end

  def spamtrap_invoke_on_trap(reason, on_trap_opt, honeypot)
    callback = on_trap_opt == :global ? Spamtrap.on_trap : on_trap_opt
    return unless callback.respond_to?(:call)

    payload = { reason: reason, request: request, controller: self, honeypot: honeypot.to_s, params: params }
    # Procs report :parameters directly; other callables (methods, etc.) need it via #method(:call).
    parameters = callback.respond_to?(:parameters) ? callback.parameters : callback.method(:call).parameters

    if parameters.any? { |type, _| type == :keyrest }
      callback.call(**payload)
    elsif parameters.any? { |type, _| type == :key || type == :keyreq }
      names = parameters.select { |type, _| type == :key || type == :keyreq }.map { |_, name| name }
      callback.call(**payload.slice(*names))
    elsif parameters.any? { |type, _| type == :req || type == :opt || type == :rest }
      callback.call(payload)
    else
      callback.call
    end
  rescue StandardError => e
    Rails.logger.error "Spamtrap on_trap callback raised: #{e.class}: #{e.message}"
  end

  private :spamtrap_nonce_failure, :spamtrap_too_fast?, :spamtrap_remap_params, :spamtrap_remap_hash,
          :spamtrap_strict_violation, :spamtrap_trap, :spamtrap_render_trap, :spamtrap_invoke_on_trap

end
