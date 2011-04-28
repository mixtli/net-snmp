require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Net::SNMP::OID do
  it "should instantiate valid oid with numeric" do
    oid = Net::SNMP::OID.new("1.3.6.1.2.1.2.1.0")
    oid.to_s.should eql("1.3.6.1.2.1.2.1.0")
    oid.label.should eql("ifNumber.0")
  end

  it "should instantiate valid oid with string" do
    oid = Net::SNMP::OID.new("ifNumber.0")
    oid.to_s.should eql("1.3.6.1.2.1.2.1.0")
    oid.label.should eql("ifNumber.0")
  end
end