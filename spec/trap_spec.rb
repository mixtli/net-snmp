require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

# These are currently occasionally segfaulting at random.  Other than that, they work 90% of the time ;)

describe "snmp traps" do
  it "should send a v1 trap" do
    #pending "still working on it"
    Net::SNMP::TrapSession.open(:peername => '127.0.0.1') do |sess|
      res = sess.trap
      res.should be_true
    end
  end

  it "should send a v2 inform" do
    pending "still working on it"
    did_callback = false
    Net::SNMP::TrapSession.open(:peername => '127.0.0.1', :version => '2c') do |sess|
      sess.inform(:oid => 'coldStart.0') do |op, res|
        did_callback = true
      end
    end
    Net::SNMP::Dispatcher.poll(false)
    did_callback.should be_true
  end

  it "should send v2 trap" do
    pending "still working on it"
    Net::SNMP::TrapSession.open(:peername => '127.0.0.1', :version => '2c') do |sess|
      res = sess.trap_v2(:oid => 'warmStart.0')
      res.should be_true
    end
  end
end
