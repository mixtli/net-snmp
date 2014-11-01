require 'timeout'
require 'pp'

module Net
module SNMP

Provider = Struct.new(:oid, :block)

class Agent
  include Debug

  attr_accessor :port, :socket, :packet

  def initialize(port = 161, max_packet_size = 65_000)
    @socket = UDPSocket.new
    @socket.bind("127.0.0.1", port)
    @max_packet_size = max_packet_size
    @killed = false

    # Contains blocks specified by the client to handle
    # get requests on mib subtrees
    @get_providers = []

    # Contains blocks specified by the client to handle
    # set requests on mib subtrees
    @set_providers = []
  end

  def time(label, &block)
    t_start = Time.now
    block[]
    t_end = Time.now
    info "#{label}: #{(t_end - t_start)*1000}ms"
  end

  def start(interval = 2)
    packet = nil
    loop {
      begin
        return if @killed
        timeout(interval) do
          @packet = @socket.recvfrom(@max_packet_size)
        end
        return if @killed
        time "Overall Response Time" do
          message = Message.parse(@packet)
          response_pdu = process_message(message)
          session = make_response_session_for_message(message)
          Wrapper.snmp_send(session.pointer, response_pdu.pointer).to_s
        end
      rescue Timeout::Error => timeout
        next
      end
    }
  end

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
      value = Constants::SNMP_NOSUCHOBJECT
      provider = @get_providers.first { |p| vb.oid.start_with? p.oid }
      value = provider.block.call(vb.oid) if provider
      response_pdu.add_varbind(oid: vb.oid, value: value)
    end
    response_pdu
  end

  # def proccess_set(message)
  #   response_pdu = make_response_pdu_for_message(message)
  # end

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
