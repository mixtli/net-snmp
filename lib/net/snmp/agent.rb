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

Provider = Struct.new(:oid, :block)

class Agent
  include Debug
  include Singleton

  attr_accessor :port, :socket, :packet

  def initialize
    # Contains blocks specified by the client to handle
    # get requests on mib subtrees
    @get_providers = []

    # Contains blocks specified by the client to handle
    # set requests on mib subtrees
    @set_providers = []

    # Set by `stop` (probably in an INT signal handler) to
    # indicate that the agent should stop
    @killed = false
  end

  def start(port = 161, interval = 2, max_packet_size = 65_000)
    @interval = interval
    @socket = UDPSocket.new
    @socket.bind("127.0.0.1", port)
    @max_packet_size = max_packet_size
    run_loop
  end
  alias listen start
  alias run start

  def stop
    @killed = true
  end

  def get(oid, &block)
    dotted_oid = oid[oid.length - 1] == '.' ? oid : "#{oid}."
    @get_providers.push(Provider.new(oid.to_s, block))
  end

  def set(oid, &block)
    dotted_oid = oid[oid.length - 1] == '.' ? oid : "#{oid}."
    @set_providers.push(Provider.new(oid.to_s, block))
  end

  def pdu(&block)
    @pdu_provider = block
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
          response_pdu = process_message(message)
          session = make_response_session_for_message(message)
          Wrapper.snmp_send(session.pointer, response_pdu.pointer)
          Wrapper.snmp_sess_close(session)
        end
      rescue Timeout::Error => timeout
        next
      end
    }
  end

  def process_message(message)
    case message.pdu.command
    when Constants::SNMP_MSG_GET
      proccess_get(message)
    when Constants::SNMP_MSG_SET
      proccess_set(message)
    end
  end

  def proccess_get(message)
    response_pdu = make_response_pdu_for_message(message)
    message.pdu.varbinds.each do |vb|
      provider = @get_providers.find { |p| vb.oid.to_s.start_with? p.oid }
      if provider
        value = provider.block.call(vb.oid)
        response_pdu.add_varbind(oid: vb.oid, value: value)
      else
        response_pdu.add_varbind(oid: vb.oid, type: Constants::SNMP_NOSUCHOBJECT)
      end
    end
    response_pdu
  end

  def proccess_set(message)
    response_pdu = make_response_pdu_for_message(message)
  end

  def copy_varbinds(from_pdu, to_pdu)
    from_pdu.varbinds.each do |vb|
      to_pdu.add_varbind(oid: vb.oid, value: vb.value)
    end
  end

  def make_response_pdu_for_message(message)
    response_pdu = PDU.new(Constants::SNMP_MSG_RESPONSE)
    response_pdu.reqid = message.pdu.reqid
    response_pdu.version = message.version
    response_pdu.community = message.pdu.community
    response_pdu
  end

  def make_response_session_for_message(message)
    session = Wrapper::SnmpSession.new
    session.version = message.version
    session.community = message.community_ptr
    session.community_len = message.community.length
    peername = "#{@packet[1][3]}:#{@packet[1][1]}"
    peername_ptr = FFI::MemoryPointer.new(:uchar, peername.length + 1)
    peername_ptr.write_string(peername)
    session.peername = peername_ptr
    session = Wrapper.snmp_open(session.pointer)
  end
end
end
end
