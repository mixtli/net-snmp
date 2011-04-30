require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "in a thread" do
  it "should get an oid asynchronously in a thread" do
    Net::SNMP.thread_safe = true
    did_callback = false
    puts "calling thread"
    dispatch_thread = Net::SNMP::Dispatcher.thread_loop
    puts "still here"
    Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic') do |s|
      puts "sending get"
      s.get(["sysDescr.0", "sysContact.0"]) do |op, result|
        puts "got callback"
        did_callback = true
        result.varbinds[0].value.should eql("test.net-snmp.org")
        result.varbinds[1].value.should match(/Coders/)
      end
    end
    sleep 3
    puts "joining thread"
    did_callback.should be(true)

    Thread.kill(dispatch_thread)
    Net::SNMP.thread_safe = false
  end
end
