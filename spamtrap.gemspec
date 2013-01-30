# -*- encoding: utf-8 -*-
$LOAD_PATH << File.dirname(__FILE__)
require 'lib/spamtrap/version'

spec = Gem::Specification.new do |s|
  s.name = 'spamtrap'
  s.version = Spamtrap::VERSION
  s.platform = Gem::Platform::RUBY
  s.author = 'Cedric Howe'
  s.email = 'cedric@freezerbox.com'
  s.homepage = 'http://github.com/cedric/spamtrap/'
  s.summary = 'Simple spamtrap for spambots.'
  s.description = 'Create bogus form fields (honeypots) that will be filled-in by spambots. When submitted, the form data will be discarded while still returning a 200 response.'
  s.require_paths = ['lib']
  s.files = Dir['lib/**/*.rb']
  s.required_rubygems_version = '>= 1.3.6'
  s.add_dependency('rails', '>= 2.3')
  s.test_files = Dir['test/**/*.rb']
  s.rubyforge_project = 'spamtrap'
  s.has_rdoc = true
end
