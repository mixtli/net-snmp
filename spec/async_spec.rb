require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "async" do
  context "version 1" do
    it "get should work" do
      did_callback = false
      Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic') do |s|
        s.get(["sysDescr.0", "sysContact.0"]) do |result|
          did_callback = true
          result.varbinds[0].value.should eql("test.net-snmp.org")
          result.varbinds[1].value.should match(/Coders/)
        end
      end
      Net::SNMP::Dispatcher.poll(false)
      did_callback.should be(true)
    end

    it "getnext should work" do
      puts "testing getnext"
      did_callback = false
      Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic') do |s|
        s.get_next(["sysDescr", "sysContact"]) do |result|
          did_callback = true
          #result.varbinds[0].value.should eql("test.net-snmp.org")
          #result.varbinds[1].value.should match(/Coders/)
        end
      end
      Net::SNMP::Dispatcher.poll(false)
      puts "done getnext"
      did_callback.should be(true)
    end

  end

  context "version 2" do
    it "get should work" do
      did_callback = false
      Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic', :version => '2c') do |s|
        s.get(["sysDescr.0", "sysContact.0"]) do |result|
          did_callback = true
          result.varbinds[0].value.should eql("test.net-snmp.org")
          result.varbinds[1].value.should match(/Coders/)
        end
      end
      Net::SNMP::Dispatcher.poll(false)
      did_callback.should be(true)
    end

    it "getnext should work" do
      did_callback = false
      Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic', :version => '2c') do |s|
        s.get_next(["sysDescr", "sysContact"]) do |result|
          did_callback = true
          result.varbinds[0].value.should eql("test.net-snmp.org")
          result.varbinds[1].value.should match(/Coders/)
        end
      end
      Net::SNMP::Dispatcher.poll(false)
      did_callback.should be(true)
    end
  end

  context "version 3" do
    #failing intermittently
    it "should get async using snmpv3" do
      did_callback = false
      Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :version => 3, :username => 'MD5User',:security_level => Net::SNMP::Constants::SNMP_SEC_LEVEL_AUTHNOPRIV, :auth_protocol => :md5, :password => 'The Net-SNMP Demo Password') do |sess|
          sess.get(["sysDescr.0"]) do |result|
            did_callback = true
            result.varbinds[0].value.should eql('test.net-snmp.org')
          end
          sleep(0.5)
          Net::SNMP::Dispatcher.poll(false)
          #Net::SNMP::Dispatcher.poll(false)
          puts "done poll"
          did_callback.should be(true)
      end
    end
#
#
    it "get should work" do
      did_callback = false
      sess = Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :version => 3, :username => 'MD5User',:security_level => Net::SNMP::Constants::SNMP_SEC_LEVEL_AUTHNOPRIV, :auth_protocol => :md5, :password => 'The Net-SNMP Demo Password') do |sess|
        sess.get(["sysDescr.0", "sysContact.0"]) do |result|
          did_callback = true
          result.varbinds[0].value.should eql("test.net-snmp.org")
          result.varbinds[1].value.should match(/Coders/)
        end
      end
      Net::SNMP::Dispatcher.poll(false)
      sess.close
      did_callback.should be(true)
    end

    it "getnext should work" do
      did_callback = false

      sess = Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :version => 3, :username => 'MD5User',:security_level => Net::SNMP::Constants::SNMP_SEC_LEVEL_AUTHNOPRIV, :auth_protocol => :md5, :password => 'The Net-SNMP Demo Password') do |sess|
        sess.get_next(["sysDescr", "sysContact"]) do |result|
          did_callback = true
          result.varbinds[0].value.should eql("test.net-snmp.org")
          result.varbinds[1].value.should match(/Coders/)
        end
      end
      Net::SNMP::Dispatcher.poll(false)
      sess.close
      did_callback.should be(true)
    end
  end
end