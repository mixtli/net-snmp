require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "NetSnmp" do
  it "should get single oid" do
    Net::SNMP::Session.open(:peername => "localhost", :community => "public" ) do |sess|
      result = sess.get("sysDescr.0")
    #  puts result.inspect
      result.varbinds.first.value.should match(/Darwin/)
    end
  end

  it "should get multiple oids" do
    Net::SNMP::Session.open(:peername => "127.0.0.1" ) do |sess|
      result = sess.get(["sysDescr.0", "sysName.0", "ifIndex.1"])
      result.varbinds[0].value.should match(/Darwin/)
      result.varbinds[1].value.should match(/local/)
      result.varbinds[2].value.should == 1
    end
  end
  
  it "should get multiple requests asynchronously" do
    did_callback = false
    session = Net::SNMP::Session.open(:peername => '127.0.0.1') do |s|
      s.get(["sysDescr.0", "sysName.0", "ifOutOctets.1"]) do |result|
        did_callback = true
        result.varbinds[0].value.should match(/Darwin/)
        result.varbinds[1].value.should match(/local/)
        result.varbinds[2].value.should be_kind_of(Integer)
        0
      end
    end
    sleep 1
    #session.dispatcher()
    Net::SNMP.dispatcher
    #2.times { sleep 1; Net::SNMP.dispatcher() }
    did_callback.should be(true)
  end


  it "invalid oid should return error" do
    Net::SNMP::Session.open(:peername => "127.0.0.1" ) do |sess|
      result = sess.get(["XXXsysDescr.0"])  #misspelled
      result.should be_error
    end
  end

  it "should get using snmpv3" do
    pending
    Net::SNMP::Session.open(:peername => '127.0.0.1', :version => 3, :username => 'myuser', :authprotocol => :sha1, :authkey => '0x1234', :privprotocol => :des, :privkey => '0x25252') do |sess| 
      result = sess.get("sysDescr.0")
      result.varbinds.first.value.should match(/Darwin/)
    end
  end

  it "should get async using snmpv3" do
    pending
    Net::SNMP::Session.open(:peername => '127.0.0.1', :version => 3, :username => 'myuser', :authprotocol => :sha1, :authkey => '0x1234', :privprotocol => :des, :privkey => '0x25252') do |sess| 
        s.get(["sysDescr.0", "sysName.0", "ifOutOctets.1"]) do |result|
          did_callback = true
          result.varbinds[0].value.should match(/Darwin/)
          result.varbinds[1].value.should match(/local/)
          0
        end
        Net::SNMP.dispatcher()
        did_callback.should be(true)
      result.varbinds.first.value.should match(/Darwin/)
    end
  end
  
  
  it "should set a value" do 
    Net::SNMP::Session.open(:peername => '127.0.0.1', :version => 1) do |sess|
      result = sess.set([['sysContact.0', Net::SNMP::ASN_OCTET_STR, 'yomama']])
      result.varbinds.first.value.should match(/yomama/)
      result.should_not be_error
    end
  end
     
  it "should set using snmpv3" do
    pending
    Net::SNMP::Session.open(:peername => '127.0.0.1', :version => 3, :username => 'myuser', :authprotocol => :sha1, :authkey => '0x1234', :privprotocol => :des, :privkey => '0x25252') do |sess| 
      result = sess.set([["sysDescr.0", OCTET_STRING, 'yomama']])
      result.varbinds.first.value.should match(/Darwin/)
    end
  end
  
  it "should get next an array of oids" do
    pending
    Net::SNMP::Session.open(:peername => "127.0.0.1" ) do |sess|
      result = sess.get_next(["ifIndex.1", "sysContact.0"])  
      result.varbinds.first.oid.should eql("ifIndex.2")
      result.should be_error
    end
  end
  
  it "should send a trap" do
    pending
    Net::SNMP::Session.open(:peername => '127.0.0.1') do |sess|
      result = sess.trap(nil, :enterprise => '.1.3.6.1.4.1111', :generictrap => 6, :specifictrap => 111)
      result.should be(true)
      result = sess.trap([["sysDescr.0", OCTET_STRING, 'yomama']], :enterprise => '.1.3.6.1.4.1111', :generic_trap => 6, :specific_trap => 111)
    end
  end

  it "should send a v2 trap" do
    pending
    Net::SNMP::Session.open(:peername => '127.0.0.1') do |sess|
      result = sess.trap_v2([["some.oid.0", "OCTET_STRING", "somestring"]])
      result.should be(true)
    end  
  end


  it "should send an inform" do
    pending
    Net::SNMP::Session.open(:peername => '127.0.0.1') do |sess|
      result = sess.inform_request(:oid => '.1.3.6.1.6.someshit') 
      result.should_not be_error
    end
  end
  
  it "should get_bulk_request" do
    pending
    Net::SNMP::Session.open(:peername => "127.0.0.1" ) do |sess|
      result = sess.get_bulk(["ifIndex.1", "sysContact.0"], :max_repetitions => 10)  
      result.varbinds.first.oid.should eql("ifIndex.2")
      result.should be_error
    end  
  end
  
  it "should get a table of values"
  
end
