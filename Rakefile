require 'lib/spamtrap/version'
 
task :build => :test do
  system "gem build spamtrap.gemspec"
end

task :release => :build do
  # tag and push
  system "git tag v#{Spamtrap::VERSION}"
  system "git push origin --tags"
  # push gem
  system "gem push spamtrap-#{Spamtrap::VERSION}.gem"
end
