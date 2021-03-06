# Logstash Stormshield SDS Plugin

## Documentation

This logstash plugin provides support for Stormshield Data Security logs:
 - Add human-readable category based on event ID
 - Extract filename and folder name from message in two keys _file_ and _folder_

## Developing

### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed.

- Create a new plugin or clone and existing from the GitHub [logstash-plugins](https://github.com/logstash-plugins) organization. We also provide [example plugins](https://github.com/logstash-plugins?query=example).

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies
```sh
bundle install
```

- Run tests
```sh
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-filter-SDS", :path => "/your/local/logstash-filter-SDS"
```

- Install plugin
```sh
bin/plugin install --no-verify
```

- Run Logstash with your plugin
```sh
bin/logstash -e 'filter {SDS {}}'
```

At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-filter-SDS.gemspec
```

- Install the plugin from the Logstash home
```sh
bin/plugin install /your/local/plugin/logstash-filter-SDS.gem
```

- Start Logstash and proceed to test the plugin

- Run tests
```sh
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-filter-SDS", :path => "/your/local/logstash-filter-SDS"
```

- Install plugin
```sh
bin/plugin install --no-verify
```

- Run Logstash with your plugin
```sh
bin/logstash -e 'filter {SDS {}}'
```

At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-filter-SDS.gemspec
```

- Install the plugin from the Logstash home
```sh
bin/plugin install /your/local/plugin/logstash-filter-SDS.gem
```

- Start Logstash and proceed to test the plugin
