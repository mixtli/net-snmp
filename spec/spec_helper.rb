$VERBOSE = true

$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
require 'net-snmp'
require 'rspec'
require 'rspec/autorun'

# Trap tests fail randomly due to race conditions,
# setting thread_safe should fix this
Net::SNMP::thread_safe = true

Net::SNMP::Debug.debug = false
