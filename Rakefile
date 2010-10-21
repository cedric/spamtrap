require 'lib/spamtrap/version'

desc 'Build gem.'
task :build => :test do
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
