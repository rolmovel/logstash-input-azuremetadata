# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "stud/interval"
require "socket" # for Socket.gethostname
require 'cgi'
require 'base64'
require 'openssl'
require 'uri'
require 'net/https'
require 'json'

# Generate a repeating message.
#
# Azure metadata logstash input.
# Using hashes:
#
# [source,ruby]
# ----------------------------------
# match => {
#  "namespace" => "value1"
#  "hub" => "value2"
#  "key_name" => "value3"
#  "access_key" => "value4"
#  "lifetime" => "value5"
# }
# ----------------------------------

class LogStash::Inputs::Example < LogStash::Inputs::Base
  config_name "azuremetadata"

  # If undefined, Logstash will complain, even if codec is unused.
  default :codec, "plain"

  # Azure namespace.
  config :namespace, :validate => :string
  # Azure hub.
  config :hub, :validate => :string
  # Azure key_name.
  config :key_name, :validate => :string
  # Azure access key.
  config :access_key, :validate => :string
  # Azure token lifetime.
  config :lifetime, :validate => :number, :default => 1

  # Set how frequently messages should be sent.
  #
  # The default, `1`, means send a message every second.
  config :interval, :validate => :number, :default => 1

  public
  def register
    @host = Socket.gethostname
  end # def register

  def run(queue)
    # we can abort the loop if stop? becomes true
    while !stop?
      metric = send(@namespace,@hub,@key_name,@access_key, @lifetime)
      event = LogStash::Event.new("message" => metric.body, "host" => @host)
      decorate(event)
      queue << event
      # because the sleep interval can be big, when shutdown happens
      # we want to be able to abort the sleep
      # Stud.stoppable_sleep will frequently evaluate the given block
      # and abort the sleep(@interval) if the return value is true
      Stud.stoppable_sleep(@interval) { stop? }
    end # loop
  end # def run

  def stop
    # nothing to do in this case so it is not necessary to define stop
    # examples of common "stop" tasks:
    #  * close sockets (unblocking blocking reads/accepts)
    #  * cleanup temporary files
    #  * terminate spawned threads
  end

  private 

  def sas_token(url, key_name, access_key, lifetime)
    target_uri = CGI.escape(url.downcase).gsub('+', '%20').downcase
    expires = Time.now.to_i + lifetime
    to_sign = "#{target_uri}\n#{expires}"
    signature = CGI.escape(Base64.strict_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), access_key, to_sign))).gsub('+', '%20')
    token = "SharedAccessSignature sr=#{target_uri}&sig=#{signature}&se=#{expires}&skn=#{key_name}"
  end

  def url(namespace, hub)
    "https://#{namespace}.servicebus.windows.net/#{hub}/consumergroups/$default/partitions"
  end

  def send(namespace, hub, key_name, access_key, sig_lifetime)
    uri = URI(url(namespace, hub))
    headers = {
      'Authorization' => sas_token(url(namespace, hub), key_name, access_key, sig_lifetime)
    }
    http = Net::HTTP.new(uri.host,uri.port)
    http.use_ssl = true
    req = Net::HTTP::Get.new(uri.path, initheader = headers)
    res = http.request(req)
    res
  end
end # class LogStash::Inputs::Example
