$: << '../lib'
require 'net-snmp'

Net::SNMP.init
Net::SNMP::Debug.logger = Logger.new(STDOUT)
Net::SNMP::Debug.logger.level = Logger::INFO

agent = Net::SNMP::Agent.instance

trap(:INT) {
  agent.stop
}

mib = {
  '1.3.1.1' => 1,
  '1.3.1.2' => "I'm a string"
}

# Set up the behavior for all requests coming in
# with varbinds under the '1.3' oid.
agent.provide '1.3' do

  get do
    info "Got a get request for #{oid}"
    if mib.has_key? oid_str
        reply(mib[oid_str])
    else
      no_such_object
    end
  end

  set do
    puts "Get a set request for #{oid} = #{value}"

    # Randomly fail 20% of the time
    if rand > 0.8
      info "Decided to fail... Sending WRONGTYPE errstat"
      error Net::SNMP::Constants::SNMP_ERR_WRONGTYPE
      next
    end

    if mib.has_key? oid_str
      mib[oid_str] = value
      # `ok` copies the current varbind to the response
      # (indicated success to the manager)
      ok
    else
      no_such_object
    end
  end

end

agent.listen(161)
