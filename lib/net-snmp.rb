require 'forwardable'
require 'nice-ffi'

%w(snmp snmp/error snmp/pdu snmp/wrapper snmp/session snmp/varbind snmp/mib snmp/mib/node).each do |f|
  require "#{File.dirname(__FILE__)}/net/#{f}"
end
Net::SNMP::MIB.init
Net::SNMP::MIB.read_all_mibs
Net::SNMP.init
