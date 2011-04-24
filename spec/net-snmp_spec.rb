require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe "NetSnmp" do
  it "should get an oid asynchronously in a thread" do
    did_callback = false
    session = Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'demopublic') do |s|
      s.get(["sysDescr.0", "sysContact.0"]) do |result|
        did_callback = true
        result.varbinds[0].value.should eql("test.net-snmp.org")
        result.varbinds[1].value.should match(/Coders/)
      end
    end
    Thread.new do
      while Net::SNMP::Dispatcher.poll == 0
        sleep 1
      end
    end.join
    did_callback.should be(true)
  end


#  it "should get columns" do
#    Net::SNMP::Session.open(:peername => 'localhost', :version => '2c', :community => 'public') do |sess|
#      result = sess.get_columns(['ifIndex', 'ifInOctets', 'ifOutOctets'])
#      result.size.should eql(7)
#      result['1']['ifIndex'].should eql('1')
#      result['2']['ifInOctets'].should be > 10
#    end
#  end


  it "should compare oids" do
    Net::SNMP.oid_lex_cmp('1.3.5', '1.3.7').should eql(-1)
    Net::SNMP.oid_lex_cmp('1.3.7', '1.3.5').should eql(1)
    Net::SNMP.oid_lex_cmp('1.3.7', '1.3.7.1').should eql(-1)
    Net::SNMP.oid_lex_cmp('1.3.5', '1.3.5').should eql(0)
  end



  it "should translate an oid" do

    oid = Net::SNMP::OID.new("ifDescr.1")
    oid.node.label.should eql("ifDescr")
    oid.label.should eql("ifDescr.1")
    oid.index.should eql("1")
  end








end
