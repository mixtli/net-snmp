require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "Net::SNMP::Wrapper" do
  def init_session
    community = "demopublic"
    peername = "test.net-snmp.org"
    
    @session = Net::SNMP::Wrapper::SnmpSession.new(nil)
    Net::SNMP::Wrapper.snmp_sess_init(@session.pointer)
    @session.community = FFI::MemoryPointer.from_string(community)
    @session.community_len = community.length
    @session.peername = FFI::MemoryPointer.from_string(peername)
    @session.version = Net::SNMP::Constants::SNMP_VERSION_1

    @handle = Net::SNMP::Wrapper.snmp_sess_open(@session.pointer)
    @session_struct = Net::SNMP::Wrapper.snmp_sess_session(@handle)
  end

  def make_pdu
    @pdu = Net::SNMP::Wrapper.snmp_pdu_create(Net::SNMP::Constants::SNMP_MSG_GET)
    @oid_ptr = FFI::MemoryPointer.new(:ulong, Net::SNMP::Constants::MAX_OID_LEN)
    @oid_len_ptr = FFI::MemoryPointer.new(:size_t)
    @oid_len_ptr.write_int(Net::SNMP::Constants::MAX_OID_LEN)
    puts @pdu.inspect

    Net::SNMP::Wrapper.get_node("sysDescr.0", @oid_ptr, @oid_len_ptr)
    Net::SNMP::Wrapper.snmp_pdu_add_variable(@pdu.pointer, @oid_ptr, @oid_len_ptr.read_int, Net::SNMP::Constants::ASN_NULL, nil, 0)
  end

  it "wrapper should snmpget synchronously" do
    #pending
    init_session

    make_pdu

    response_ptr = FFI::MemoryPointer.new(:pointer)
    status = Net::SNMP::Wrapper.snmp_sess_synch_response(@handle, @pdu.pointer, response_ptr)
    status.should eql(0)

    response = Net::SNMP::Wrapper::SnmpPdu.new(response_ptr.read_pointer)
    value = response.variables.val[:string].read_string(response.variables.val_len)
    value.should eql('test.net-snmp.org')
  end

  it "wrapper should snmpget asynchronously" do
      #pending
      init_session
      make_pdu
      did_callback = 0
      result = nil
      @session.callback = lambda do |operation, session, reqid, pdu_ptr, magic|
        did_callback = 1
        pdu = Net::SNMP::Wrapper::SnmpPdu.new(pdu_ptr)
        variables = Net::SNMP::Wrapper::VariableList.new(pdu.variables)
        result = variables.val[:string].read_string(variables.val_len)
        0
      end
      sess = Net::SNMP::Wrapper.snmp_open(@session.pointer)
      Net::SNMP::Wrapper.snmp_send(sess.pointer, @pdu)
      sleep 1
      fdset = FFI::MemoryPointer.new(:pointer, Net::SNMP::Inline.fd_setsize / 8)
      fds = FFI::MemoryPointer.new(:int)
      #fds.autorelease = false
      tval = Net::SNMP::Wrapper::TimeVal.new
      block = FFI::MemoryPointer.new(:int)
      #block.autorelease = false
      block.write_int(1)
      Net::SNMP::Wrapper.snmp_select_info(fds, fdset, tval.pointer, block )
      FFI::LibC.select(fds.read_int, fdset, nil, nil, nil)
      Net::SNMP::Wrapper.snmp_read(fdset)
      did_callback.should be(1)
      result.should eql('test.net-snmp.org')
  end
end
