$LOAD_PATH.unshift(File.dirname(__FILE__))
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))
require 'net-snmp'
require 'rspec'
require 'rspec/autorun'

Net::SNMP::Debug.debug = true
#Spec::Runner.configure do |config|
  
#end
