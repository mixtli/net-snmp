#!/usr/bin/env ruby
require 'optparse'
#require 'ruby-debug19'
$LOAD_PATH.unshift(File.dirname(__FILE__) + "/../lib")

require 'net-snmp'
options = {}

optparse = OptionParser.new do|opts|
  opts.banner = "Usage: snmpget.rb -v [1,2,3] -c <community> <host> <oid>"
  opts.on( '-v', '--version VERSION', 'SNMP version' ) do |version|
    options[:version] = version
  end
  
  opts.on('-c', '--community COMMUNITY', 'Community') do |community|
    options[:community] = community
  end
end
 optparse.parse!
host = ARGV[0]
oid = ARGV[1]

sess = Net::SNMP::Session.new(:peername => host, :community => options[:community], :version => options[:version])

pdu = sess.get(oid)

pdu.varbinds.each do |v|
  puts v.name
  puts v.value
end
