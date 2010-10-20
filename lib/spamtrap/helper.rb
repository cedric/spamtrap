class ActionView::Helpers::FormBuilder
  def spamtrap(parameter='spamtrap', options={})
    # parameter ||= @template.controller.spamtrap_parameter || 'spamtrap'
    options.reverse_merge({:class => 'spamtrap'})
    @template.content_tag(:div, options) do
      @template.label_tag(parameter) +
      @template.text_field_tag(parameter)
    end
  end
end
