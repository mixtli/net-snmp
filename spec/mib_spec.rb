require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Net::SNMP::MIB::Node do
  it "should get info for sysDescr" do
    node = Net::SNMP::MIB::Node.get_node("sysDescr")
    node.label.should eq("sysDescr")
  end

  it "should get parent" do
    node = Net::SNMP::MIB::Node.get_node("sysDescr")
    node.parent.label.should eq("system")
  end

  it "should get node children" do
    node = Net::SNMP::MIB::Node.get_node("ifTable")
    if_entry = node.children.first
    if_entry.label.should eql("ifEntry")
    if_entry.children.should include { |n| n.label == "ifIndex" }
  end

  it "should get siblings" do
    node = Net::SNMP::MIB::Node.get_node("sysDescr")
    node.siblings.should include { |n| puts "TESTING #{n.label}"; n.label == "sysName" }
  end

  it "should get oid" do
    node = Net::SNMP::MIB::Node.get_node("sysDescr")
    node.oid.name.should eq("1.3.6.1.2.1.1.1")
  end

  it "should get by oid" do
    node = Net::SNMP::MIB::Node.get_node("1.3.6.1.2.1.1.1")
    node.label.should eq("sysDescr")
  end

  it "should do stuff" do
    node = Net::SNMP::MIB::Node.get_node("ipAdEntIfIndex")
  end

end
