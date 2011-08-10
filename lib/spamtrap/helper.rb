class ActionView::Helpers::FormBuilder
  def spamtrap(parameter='spamtrap', options={})
    options.reverse_merge!({:class => 'spamtrap'})
    @template.text_area_tag(parameter, nil, options)
  end
end
