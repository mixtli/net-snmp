require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Net::SNMP::Utility do
  it "should compare oids" do
    Net::SNMP::Utility.oid_lex_cmp('1.3.5', '1.3.7').should eql(-1)
    Net::SNMP::Utility.oid_lex_cmp('1.3.7', '1.3.5').should eql(1)
    Net::SNMP::Utility.oid_lex_cmp('1.3.7', '1.3.7.1').should eql(-1)
    Net::SNMP::Utility.oid_lex_cmp('1.3.5', '1.3.5').should eql(0)
  end
end
