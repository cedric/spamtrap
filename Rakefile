# -*- encoding: utf-8 -*-
$LOAD_PATH << File.dirname(__FILE__)
require 'rake/testtask'
require 'lib/spamtrap/version'

namespace :gem do

  desc 'Run tests.'
  Rake::TestTask.new(:test) do |test|
    test.libs << 'lib' << 'test'
    test.pattern = 'test/**/*_test.rb'
    test.verbose = true
  end

  desc 'Build gem.'
  task :build do
    system "gem build spamtrap.gemspec"
  end

  desc 'Build, tag and push gem.'
  task :release => :build do
    # tag and push
    system "git tag v#{Spamtrap::VERSION}"
    system "git push origin --tags"
    # push gem
    system "gem push spamtrap-#{Spamtrap::VERSION}.gem"
  end

end

task :default => 'gem:test'
