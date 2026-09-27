module Spamtrap
  class Railtie < Rails::Railtie
    # on_load so the patches land after app initializers, not at require time.
    initializer 'spamtrap.install' do
      ActiveSupport.on_load(:action_controller_base) { Spamtrap.install_controller! }
      ActiveSupport.on_load(:action_controller_api)  { Spamtrap.install_controller! }
      ActiveSupport.on_load(:action_view) { Spamtrap.install_form_builder! }
      # A FormBuilder built before any view renders (e.g. in ActionView::TestCase) would
      # miss the on_load hook, so patch now if the form helpers are already loaded.
      Spamtrap.install_form_builder! if Spamtrap.form_builder_loaded?
    end
  end
end
