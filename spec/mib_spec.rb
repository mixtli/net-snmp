require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Net::SNMP::MIB::Node do
  it "should get info for sysDescr" do
    node = Net::SNMP::MIB::Node.get_node("sysDescr")
    node.label.should eq("sysDescr")
  end
  
  it "should get parent" do
    node = Net::SNMP::MIB::Node.get_node("sysDescr")
    node.parent.label.should eq("system")
   #   puts node.parent.inspect
  end
  
  it "should get children" do
    node = Net::SNMP::MIB::Node.get_node("system")
    node.children.each do |c|
    #  puts c.inspect
    end
  end
  
  it "should get siblings" do
    node = Net::SNMP::MIB::Node.get_node("sysDescr")
    node.siblings.should include{|n| n.label == "sysName"}
    puts node.siblings.map(&:label)
  end

  it "should get oid" do
    node = Net::SNMP::MIB::Node.get_node("sysDescr")
    puts node.struct.inspect
    node.oid.should eq("1.3.6.1.2.1.1.1")
  end
  
  it "should get by oid" do
    node = Net::SNMP::MIB::Node.get_node("1.3.6.1.2.1.1.1")
    node.label.should eq("sysDescr")
  end
  
  
end
