require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "snmp traps" do
  it "should send a v1 trap" do
    pending "still working on it"
    Net::SNMP::Session.open(:peername => '127.0.0.1') do |sess|
      res = sess.trap
      res.should be_true
    end
  end

  it "should send a v2 inform" do
    pending "still working on it"
    did_callback = false

    Net::SNMP::Session.open(:peername => '127.0.0.1', :version => '2c') do |sess|
      sess.inform do |res|
        did_callback = true
      end
    end
    did_callback.should be_true
  end

  it "should send v2 trap" do
    pending "still working on it"
    Net::SNMP::Session.open(:peername => '127.0.0.1', :version => '2c') do |sess|
      res = sess.trap_v2
      res.should be_true
    end
  end
end