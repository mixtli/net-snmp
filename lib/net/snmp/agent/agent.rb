# Responsibility:
#  - Manages the request/response cycle for incoming messages
#    + Listens for incoming requests
#    + Parses request packets into Message objects
#    + Dispatches the messages to (sub) Agents
#    + Serializes the response from the subagents and sends it to the caller

require 'singleton'
require 'timeout'
require 'pp'

module Net
module SNMP

class Agent
  include Debug
  include Singleton

  attr_accessor :port, :socket, :packet, :providers

  def initialize
    @providers = []

    # Set by `stop` (probably in an INT signal handler) to
    # indicate that the agent should stop
    @killed = false
  end

  def start(port = 161, interval = 2, max_packet_size = 65_000)
    @interval = interval
    @socket = UDPSocket.new
    @socket.bind("127.0.0.1", port)
    @max_packet_size = max_packet_size
    info "Agent listening on port #{port}"
    run_loop
  end
  alias listen start
  alias run start

  def stop
    @killed = true
  end

  def pdu(&block)
    @pdu_provider = block
  end

  def provide(oid, &block)
    # Need a trailing dot on the oid so we can avoid
    # considering 1.3.22 a child of 1.3.2
    dotted_oid = oid.end_with?('.') ? oid : "#{oid}."
    provider = Provider.new(dotted_oid)
    provider.instance_eval(&block)
    providers << provider
  end

  private

  def run_loop
    packet = nil
    loop {
      begin
        return if @killed
        timeout(@interval) do
          @packet = @socket.recvfrom(@max_packet_size)
        end
        return if @killed
        time "Overall Response Time" do
          message = Message.parse(@packet)
          response_pdu = RequestDispatcher.dispatch(message, providers)
          Session.open(peername: @packet[1][3], port: @packet[1][1], version: message.version_name) do |sess|
            sess.send_pdu response_pdu
          end
        end
      rescue Timeout::Error => timeout
        next
      end
    }
  end

end
end
end
