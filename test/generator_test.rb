require File.join(File.dirname(__FILE__), 'test_helper')

require 'rails/generators'
require 'rails/generators/test_case'
require 'generators/spamtrap/install/install_generator'

class GeneratorTest < Rails::Generators::TestCase
  tests Spamtrap::Generators::InstallGenerator
  destination File.expand_path('tmp', __dir__)
  setup :prepare_destination

  def test_creates_the_initializer
    run_generator
    assert_file 'config/initializers/spamtrap.rb'
  end

  def test_initializer_documents_known_defaults
    run_generator
    assert_file 'config/initializers/spamtrap.rb' do |content|
      assert_match(/^# Spamtrap\.min_fill_time = 1$/, content)
      assert_match(/^# Spamtrap\.mutate = false$/, content)
    end
  end

  # Parses lib/spamtrap.rb's `class << self` block for every attr_writer/attr_accessor
  # name, so the template can't silently drift when an option is added or renamed.
  def test_initializer_documents_every_spamtrap_option
    spamtrap_rb = File.read(File.expand_path('../lib/spamtrap.rb', __dir__))
    option_names = spamtrap_rb.scan(/^\s*attr_(?:writer|accessor)\s+(.+)$/).flatten
                              .flat_map { |names| names.split(',') }
                              .map { |name| name.strip.delete_prefix(':') }

    refute_empty option_names, 'expected to find at least one attr_writer/attr_accessor in lib/spamtrap.rb'

    run_generator
    template = File.read(File.expand_path('config/initializers/spamtrap.rb', destination_root))

    option_names.each do |option|
      assert_match(/Spamtrap\.#{Regexp.escape(option)}\s*=/, template,
                    "expected the generated initializer to document Spamtrap.#{option}")
    end
  end
end
