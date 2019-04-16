#! /usr/bin/env ruby
#
#   check-logstash-queue-depth
#
# DESCRIPTION:
#   This plugin uses the Logstash node info API to check the depth of the logstash persistent queue
#
# OUTPUT:
#   check status
#
# PLATFORMS:
#   Linux
#
# DEPENDENCIES:
#   gem: sensu-plugin
#   gem: rest-client
#
# USAGE:
#   #YELLOW
#
# NOTES:
#
# LICENSE:
#   Copyright 2011 Sonian, Inc <chefs@sonian.net>
#   Copyright 2018 Philipp Hellmich <phil@hellmi.de>
#   Released under the same terms as Sensu (the MIT license); see LICENSE
#   for details.
#

require 'sensu-plugin/check/cli'
require 'rest-client'
require 'json'
require 'base64'

#
# Logstash Queue Depth check
#
class LogstashQueueDepth < Sensu::Plugin::Check::CLI

  option :host,
         description: 'Logstash server host',
         short: '-h HOST',
         long: '--host HOST',
         default: 'localhost'

  option :port,
         description: 'Logstash monitoring port',
         short: '-p PORT',
         long: '--port PORT',
         proc: proc(&:to_i),
         default: 9600

  option :user,
         description: 'Logstash user',
         short: '-u USER',
         long: '--user USER'

  option :password,
         description: 'Logstash password',
         short: '-P PASS',
         long: '--password PASS'

  option :https,
         description: 'Enables HTTPS',
         short: '-e',
         long: '--https'

  option :warning,
         description: 'Enqueued messages WARNING threshold',
         short: '-w EVENT_COUNT',
         long: '--warn EVENT_COUNT',
         default: 10000

  option :critical,
         description: 'Enqueued messages CRITICAL threshold',
         short: '-c EVENT_COUNT',
         long: '--crit EVENT_COUNT',
         default: 100000

  def get_logstash_resource(resource)
    headers = {}
    if config[:user] && config[:password]
      auth = 'Basic ' + Base64.encode64("#{config[:user]}:#{config[:password]}").chomp
      headers = { 'Authorization' => auth }
    end

    protocol = if config[:https]
                 'https'
               else
                 'http'
               end

    r = RestClient::Resource.new("#{protocol}://#{config[:host]}:#{config[:port]}#{resource}", timeout: config[:timeout], headers: headers)
    JSON.parse(r.get)
  rescue Errno::ECONNREFUSED
    warning 'Connection refused'
  rescue RestClient::RequestTimeout
    warning 'Connection timed out'
  end

  def run
    stats = get_logstash_resource('/_node/stats')

    timestamp = Time.now.to_i
    node = stats

    metrics = {}

    # logstash < 6.0
    if node.key?('pipeline')
      if node['pipeline'].key?('queue') and node['pipeline']['queue']['type'] == 'persisted'
        metrics['queue.events'] = node['pipeline']['queue']['events']
        metrics['queue.size_in_bytes'] = node['pipeline']['queue']['capacity']['queue_size_in_bytes']
        metrics['queue.free_space_in_bytes'] = node['pipeline']['queue']['data']['free_space_in_bytes']
        metrics['queue.events'] = node['pipeline']['queue']['events']
      end

    # logstash >= 6.0
    elsif node.key?('pipelines')
      node['pipelines'].each_key do |pipeline|
        if node['pipelines'][pipeline].key?('queue') and node['pipeline'][pipeline]['queue']['type'] == 'persisted'
          metrics["#{pipeline}.queue.events"] = node['pipeline'][pipeline]['queue']['events']
          metrics["#{pipeline}.queue.size_in_bytes"] = node['pipeline'][pipeline]['queue']['capacity']['queue_size_in_bytes']
          metrics["#{pipeline}.queue.free_space_in_bytes"] = node['pipeline'][pipeline]['queue']['data']['free_space_in_bytes']
        end
      end
    end

    critical_state = false
    warning_state = false
    if node.key?('pipelines')
      size_queue_text = ""
      metrics['pipelines'].each_key do |pipeline|
        size_queue_text = "Queued events: %s, size in bytes: %s, free space in bytes: %s; %s" %
            [metrics["#{pipeline}.queue.events"].to_s, metrics["#{pipeline}.queue.size_in_bytes"], metrics["#{pipeline}.queue.free_space_in_bytes"], size_queue_text]
        critical_state = true if metrics["#{pipeline}.queue.events"].to_i > config[:critical].to_i
        warning_state = true if metrics["#{pipeline}.queue.events"].to_i > config[:warning].to_i
      end
    else
      size_queue_text = "Queued events: %s, size in bytes: %s, free space in bytes: %s" %
          [metrics['queue.events'].to_s, metrics['queue.size_in_bytes'], metrics['queue.free_space_in_bytes']]
      critical_state =  size_queue_text if metrics['queue.events'].to_i > config[:critical].to_i
      warning_state = size_queue_text if metrics['queue.events'].to_i > config[:warning].to_i
    end

    critical size_queue_text if critical_state
    warning size_queue_text if warning_state
    ok size_queue_text
  end
end
