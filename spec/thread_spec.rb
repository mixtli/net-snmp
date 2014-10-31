require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "in a thread" do
  it "should get an oid asynchronously in a thread" do
    Net::SNMP.thread_safe = true
    did_callback = false
    dispatch_thread = Net::SNMP::Dispatcher.thread_loop
    Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic') do |s|
      s.get(["sysDescr.0", "sysContact.0"]) do |op, result|
        did_callback = true
        result.varbinds[0].value.should eql("test.net-snmp.org")
        result.varbinds[1].value.should match(/Coders/)
      end
    end
    sleep 3
    did_callback.should be(true)

    Thread.kill(dispatch_thread)
    Net::SNMP.thread_safe = false
  end
end
