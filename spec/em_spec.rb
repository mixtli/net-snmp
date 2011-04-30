require File.expand_path(File.dirname(__FILE__) + '/spec_helper')
require 'eventmachine'

describe "em" do
  
  it "should work in event_machine" do
    did_callback = false
    EM.run do
      Net::SNMP::Dispatcher.em_loop

      session = Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic') do |s|
        s.get("sysDescr.0") do |op, result|
          did_callback = true
          result.varbinds[0].value.should eql("test.net-snmp.org")
        end
      end

      EM.add_timer(3) do
        did_callback.should be_true
        EM.stop
      end
    end
  end


end