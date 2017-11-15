Gem::Specification.new do |s|
  s.name = 'logstash-filter-SDS'
  s.version = '1.0.0'
  s.licenses = ['Stormshield']
  s.summary = "SDS filter."
  s.description = "SDS filter"
  s.authors = ["Stormshield"]
  s.email = 'svc@stormshield.eu'
  s.homepage = "http://www.stormshield.eu"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core-plugin-api', '>= 1.60', '<= 2.99'
  s.add_development_dependency "logstash-devutils", "= 1.3.4"
end
