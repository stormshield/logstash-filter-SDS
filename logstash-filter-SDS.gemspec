Gem::Specification.new do |s|
  s.name = 'logstash-filter-SDS'
  s.version = '0.3'
  s.licenses = ['Stormshield']
  s.summary = "SDS filter."
  s.description = "SDS filter"
  s.authors = ["Stormshield"]
  s.email = 'svc@stormshield.eu'
  s.homepage = "http://www.stormshield.eu"
  s.require_paths = ["lib"]

  # Files
  s.files = [
'.gitignore',
'CHANGELOG.md',
'CONTRIBUTORS',
'DEVELOPER.md',
'Gemfile',
'LICENSE',
'NOTICE.TXT',
'README.md',
'Rakefile',
'lib/logstash/filters/SDS.rb',
'logstash-filter-SDS.gemspec',
'spec/filters/SDS_spec.rb',
'spec/spec_helper.rb'
  ]
  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", ">= 2.0.0", "< 3.0.0"
  s.add_development_dependency 'logstash-devutils', "~> 0"
end
