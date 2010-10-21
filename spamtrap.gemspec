# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib/', __FILE__)
$:.unshift lib unless $:.include?(lib)
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
  s.files = Dir['lib/**/*.rb']
  s.require_paths = ['lib']
  s.add_dependency('rails')
  s.rubyforge_project = 'spamtrap'
  s.has_rdoc = true
end
