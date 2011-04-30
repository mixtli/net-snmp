require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require 'eventmachine'

describe "snmp errors" do
  it "should rescue a timeout error" do
    Net::SNMP::Session.open(:peername => 'www.yahoo.com') do |sess|
      begin
        sess.get("sysDescr.0")
      rescue Net::SNMP::Error => e
        e.print
        e.status.should eql(Net::SNMP::Constants::STAT_TIMEOUT)
      end
    end
  end

  it "should rescue timeout error in a fiber" do
    got_error = false
    EM.run {
      Fiber.new {
        Net::SNMP::Dispatcher.fiber_loop
        Net::SNMP::Session.open(:peername => 'www.yahoo.com') do |sess|
          begin
            puts "sending get pdu"
            sess.get("sysDescr.0")
            puts "done sess.get"
          rescue Net::SNMP::TimeoutError => e
            got_error = true
          end
        end
        EM.stop
      }.resume(nil)
    }
    got_error.should be_true        
  end

end