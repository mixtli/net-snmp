module Net
module SNMP
class Message
  include SNMP::Debug

  def self.parse(packet)
    Message.new(packet)
  end

  # Could have been an instance method, but a response pdu
  # isn't really an intrinsic property of all messages. So,
  # going with class method instead.
  def self.response_pdu_for(message)
    response_pdu = PDU.new(Constants::SNMP_MSG_RESPONSE)
    response_pdu.reqid = message.pdu.reqid
    response_pdu.version = message.version
    response_pdu.community = message.pdu.community
    response_pdu
  end

  attr_accessor :version, :community, :pdu, :version_ptr, :community_ptr

  def version_name
    case @version
    when Constants::SNMP_VERSION_1
      '1'
    when Constants::SNMP_VERSION_2c
      '2c'
    when Constants::SNMP_VERSION_3
      '3'
    else
      raise "Invalid SNMP version: #{@version}"
    end
  end

  private

  attr_accessor :type,
    :length,
    :data,
    :cursor,
    :bytes_remaining

  def initialize(packet)
    @version = nil
    @version_ptr = FFI::MemoryPointer.new(:long, 1)
    @community_ptr = FFI::MemoryPointer.new(:uchar, 100)
    @packet = packet
    @packet_length = packet[0].length
    @type_ptr = FFI::MemoryPointer.new(:int, 1)
    @data_ptr = FFI::MemoryPointer.new(:char, @packet_length)
    @data_ptr.write_bytes(packet[0])
    @cursor_ptr = @data_ptr
    @bytes_remaining_ptr = FFI::MemoryPointer.new(:int, 1)
    @bytes_remaining_ptr.write_bytes([@packet_length].pack("L"))
    debug "MESSAGE INITIALIZED\n#{self}"
    parse
  end

  def parse
    parse_length
    parse_version
    parse_community
    parse_pdu
    self
  end

  def parse_length
    @cursor_ptr = Net::SNMP::Wrapper.asn_parse_header(@data_ptr, @bytes_remaining_ptr, @type_ptr)
    unless @type_ptr.read_int == 48
      raise "Invalid SNMP packet. Message should start with a sequence declaration"
    end
    debug "MESSAGE SEQUENCE HEADER PARSED\n#{self}"
  end

  def parse_version
    @cursor_ptr = Net::SNMP::Wrapper.asn_parse_int(
      @cursor_ptr,
      @bytes_remaining_ptr,
      @type_ptr,
      @version_ptr,
      @version_ptr.total)

    @version = @version_ptr.read_long
    debug "VERSION NUMBER PARSED\n#{self}"
  end

  def parse_community
    community_length_ptr = FFI::MemoryPointer.new(:size_t, 1)
    community_length_ptr.write_int(@community_ptr.total)
    @cursor_ptr = Net::SNMP::Wrapper.asn_parse_string(
      @cursor_ptr,
      @bytes_remaining_ptr,
      @type_ptr,
      @community_ptr,
      community_length_ptr)

    @community = @community_ptr.read_string
    debug "COMMUNITY PARSED\n#{self}"
  end

  def parse_pdu
    pdu_struct_ptr = Net::SNMP::Wrapper::SnmpPdu.new
    Net::SNMP::Wrapper.snmp_pdu_parse(pdu_struct_ptr, @cursor_ptr, @bytes_remaining_ptr)
    @pdu = Net::SNMP::PDU.new(pdu_struct_ptr.pointer)
    debug "COMMUNITY PARSED\n#{self}"
  end

  def to_s
    <<-EOF
    version(#{@version})
    community(#{@community})
    pdu
      command(#{@pdu.command if @pdu})
      varbinds (#{@pdu.varbinds.map{|v| "\n          #{v.oid.to_s} => #{v.value}" }.join('') if @pdu})
    type(#{@type_ptr.read_int})
    bytes_remaining(#{@bytes_remaining_ptr.read_int})
    cursor @ #{@cursor_ptr.address}
      Byte:  #{indices = []; (@bytes_remaining_ptr.read_int.times {|i| indices.push((i+1).to_s.rjust(2))}; indices.join ' ')}
      Value: #{@cursor_ptr.get_bytes(0, @bytes_remaining_ptr.read_int).each_byte.map {|b| b.to_s(16).rjust(2, '0') }.join(' ')}
    data @ #{@data_ptr.address}
      #{@data_ptr.get_bytes(0, @packet_length).each_byte.map {|b| b.to_s(16).rjust(2, '0') }.join(' ')}
    EOF
  end
end
end
end
