$: << '../lib'

require 'net-snmp'

Net::SNMP::Session.open(:peername => "localhost", :community => "public" ) do |session|
  t_start = Time.now
  pdu = session.get(["1.3.6.1.4.1.290.6.7.3.1.3.6.0", '1.3.6.1.4.1.290.6.7.3.1.3.7.0'])
  t_end = Time.now
  puts "Got #{pdu.varbinds[0].value} & #{pdu.varbinds[1].value} in #{(t_end - t_start) * 1000} ms"
end
