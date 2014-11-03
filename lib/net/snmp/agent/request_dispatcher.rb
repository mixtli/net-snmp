# RequestDispatcher module handles calling all required providers for a request
# in the context of a RequestContext object (which itself provides the agent DSL)

module Net::SNMP
  module RequestDispatcher

    def self.dispatch(message, providers)
      response_pdu = Message::response_pdu_for(message)
      context = RequestContext.new
      context.message = message
      context.response_pdu = response_pdu
      message.pdu.varbinds.each do |vb|
        context.varbind = vb
        provider = providers.select { |p| vb.oid.to_s.start_with?(p.oid.to_s)}
        handler = providers[0].handler_for(message)
        context.instance_exec(&handler)
      end
      response_pdu
    end

  end
end
