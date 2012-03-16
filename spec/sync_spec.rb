require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require 'pp'

describe "synchronous calls" do
  # To test sets, you have to have a local snmpd running with write permissions
  context "version 1" do
    it "get should succeed" do
      Net::SNMP::Session.open(:peername => "test.net-snmp.org", :community => "demopublic" ) do |sess|
        result = sess.get("sysDescr.0")
        result.varbinds.first.value.should eql("test.net-snmp.org")
      end
    end

    it "multiple calls within session should succeed" do
      Net::SNMP::Session.open(:peername => "test.net-snmp.org", :community => "demopublic" ) do |sess|
        result = sess.get("sysDescr.0")
        result.varbinds.first.value.should eql("test.net-snmp.org")
        second = sess.get("sysName.0")
        second.varbinds.first.value.should eql("test.net-snmp.org")
      end
    end
    it "get should succeed with multiple oids" do
      Net::SNMP::Session.open(:peername => "test.net-snmp.org", :community => 'demopublic' ) do |sess|
        result = sess.get(["sysDescr.0", "sysName.0"])
        result.varbinds[0].value.should eql("test.net-snmp.org")
        result.varbinds[1].value.should eql("test.net-snmp.org")
      end
    end

    it "set should succeed" do
      Net::SNMP::Session.open(:peername => '127.0.0.1', :version => 1, :community => 'private') do |sess|
        result = sess.set([['sysContact.0', Net::SNMP::Constants::ASN_OCTET_STR, 'yomama']])
        result.varbinds.first.value.should match(/yomama/)
        result.should_not be_error
      end
    end

    it "getnext should succeed" do
      Net::SNMP::Session.open(:peername => "test.net-snmp.org", :community => "demopublic" ) do |sess|
        result = sess.get_next(["sysUpTimeInstance.0"])
        result.varbinds.first.oid.oid.should eql("1.3.6.1.2.1.1.4.0")
        result.varbinds.first.value.should match(/Net-SNMP Coders/)
      end
    end


    it "getbulk should succeed" do
      Net::SNMP::Session.open(:peername => "test.net-snmp.org" , :version => '2c', :community => 'demopublic') do |sess|
        result = sess.get_bulk(["sysContact.0"], :max_repetitions => 10)
        result.varbinds.first.oid.name.should eql("1.3.6.1.2.1.1.5.0")
        result.varbinds.first.value.should eql("test.net-snmp.org")
      end
    end

    it "getbulk should succeed with multiple oids" do
      Net::SNMP::Session.open(:peername => "localhost" , :version => '2c', :community => 'public') do |sess|
        result = sess.get_bulk(["ifInOctets", 'ifOutOctets', 'ifInErrors', 'ifOutErrors'], :max_repeaters =>10)
        result.varbinds.size.should eql(40)
      end
    end

    it "get should return error with invalid oid" do
      Net::SNMP::Session.open(:peername => "test.net-snmp.org", :community => "demopublic" ) do |sess|
        result = sess.get(["XXXsysDescr.0"])  #misspelled
        result.should be_error
      end
    end

    it "get_table should work" do
      #pending "not yet implemented"
      session = Net::SNMP::Session.open(:peername => "localhost", :version => '1')
      table = session.table("ifEntry")
      table['1']['ifIndex'].should eql(1)
      table['2']['ifIndex'].should eql(2)
    end

    it "walk should work" do
      #pending "not yet implemented"
      session = Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :version => 1, :community => 'demopublic')
      results = session.walk("system")
      results['1.3.6.1.2.1.1.1.0'].should match(/test.net-snmp.org/)
    end

    it "walk should work with multiple oids" do
      Net::SNMP::Session.open(:peername => 'localhost', :version => 1) do |sess|
        sess.walk(['system', 'ifTable']) do |results|
          #pp results
          results['1.3.6.1.2.1.1.1.0'].should match(/Darwin/)
          results['1.3.6.1.2.1.2.2.1.1.2'].should eql(2)
          results.size.should eql(208)
        end
      end
    end

    it "get_columns should work" do
      Net::SNMP::Session.open(:peername => 'localhost') do |sess|
        table = sess.columns(['ifIndex', 'ifDescr', 'ifType'])
        table['1']['ifIndex'].should eql(1)
        table['2']['ifDescr'].should eql('gif0')
      end
    end

    it "get a value with oid type should work" do
      Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic') do |sess|
        res = sess.get("sysORID.1")
        res.varbinds.first.value.to_s.should eql('1.3.6.1.6.3.1')
      end
    end
  end

  context "version 2" do
    
  end

  context "version 3" do
    it "should get using snmpv3" do
      #pending
      Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :version => 3, :username => 'MD5User', :security_level => Net::SNMP::Constants::SNMP_SEC_LEVEL_AUTHNOPRIV, :auth_protocol => :md5, :password => 'The Net-SNMP Demo Password') do |sess|
        result = sess.get("sysDescr.0")
        result.varbinds.first.value.should eql('test.net-snmp.org')
      end
    end
    it "should set using snmpv3" do
      pending
      Net::SNMP::Session.open(:peername => '127.0.0.1', :version => 3, :username => 'myuser', :auth_protocol => :sha1, :password => '0x1234') do |sess|
        result = sess.set([["sysDescr.0", Net::SNMP::Constants::ASN_OCTET_STR, 'yomama']])
        result.varbinds.first.value.should match(/Darwin/)
      end
    end

    it "should get using authpriv" do
      Net::SNMP::Session.open(:peername => '127.0.0.1', :version => 3, :username => 'mixtli', :security_level => Net::SNMP::Constants::SNMP_SEC_LEVEL_AUTHPRIV, :auth_protocol => :md5, :priv_protocol => :des, :auth_password => 'testauth', :priv_password => 'testpass') do |sess|
        result = sess.get("sysDescr.0")
        result.varbinds.first.value.should match(/xenu/)
      end
    end
  end
end
