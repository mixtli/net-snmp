require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require 'eventmachine'
require 'fiber'

describe "in fiber" do

  def wrap_fiber
    EM.run do
      Net::SNMP::Dispatcher.fiber_loop
      Fiber.new { yield; EM.stop }.resume(nil)
    end
  end


  it "get should work in a fiber with synchronous calling style" do
    #pending
    wrap_fiber do
        session = Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic')
        result = session.get("sysDescr.0")
        puts "got result = #{result}"
        result.varbinds[0].value.should eql("test.net-snmp.org")
    end
  end

  it "getnext" do
    #pending
    wrap_fiber do
      Net::SNMP::Session.open(:peername => "test.net-snmp.org", :community => "demopublic" ) do |sess|
        result = sess.get_next(["sysUpTimeInstance.0"])
        result.varbinds.first.oid.oid.should eql("1.3.6.1.2.1.1.4.0")
        result.varbinds.first.value.should match(/Net-SNMP Coders/)
      end
    end
  end

  it "should get using snmpv3" do
    #pending
    wrap_fiber do
      Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :version => 3, :username => 'MD5User', :security_level => Net::SNMP::Constants::SNMP_SEC_LEVEL_AUTHNOPRIV, :auth_protocol => :md5, :password => 'The Net-SNMP Demo Password') do |sess|
        result = sess.get(["sysDescr.0"])
        result.varbinds.first.value.should eql('test.net-snmp.org')
      end
    end
  end

end
