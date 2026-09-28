# -*- encoding: utf-8 -*-
require_relative 'lib/spamtrap/version'

spec = Gem::Specification.new do |s|
  s.name = 'spamtrap'
  s.version = Spamtrap::VERSION
  s.platform = Gem::Platform::RUBY
  s.license = 'MIT'
  s.author = 'Cedric Howe'
  s.email = 'cedric@freezerbox.com'
  s.homepage = 'https://github.com/cedric/spamtrap/'
  s.summary = 'Simple spamtrap for spambots.'
  s.description = 'Create bogus form fields (honeypots) that will be filled-in by spambots. When submitted, the form data will be discarded while still returning a 200 response.'
  s.require_paths = ['lib']
  s.files = Dir['lib/**/*']
  s.required_ruby_version = '>= 3.1.0'
  s.required_rubygems_version = '>= 1.3.6'
  s.add_dependency('actionpack', '>= 7.2', '< 9')
  s.add_dependency('actionview', '>= 7.2', '< 9')
  s.add_dependency('railties',   '>= 7.2', '< 9')
  s.add_development_dependency('rake')
  s.add_development_dependency('minitest')
  s.add_development_dependency('activemodel') # form_with_errors tests only
end
