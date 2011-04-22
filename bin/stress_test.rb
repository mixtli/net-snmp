#!/usr/bin/env ruby
require 'optparse'
$LOAD_PATH.unshift(File.dirname(__FILE__) + "/../lib")

require 'net-snmp'

Net::SNMP::Session.open do |sess|
  loop do
    200.times {
      pdu = sess.get('ifIndex.1')
      puts pdu.varbinds.first.value
     pdu.free
    }
    sleep 1
  end
end
