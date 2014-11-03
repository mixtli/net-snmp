module Net
module SNMP
class Provider
  attr_accessor :oid,
    :get_handler,
    :set_handler,
    :get_next_handler,
    :get_bulk_handler

  def initialize(oid)
    @oid = oid
  end

  def handler_for(command)
    # User might be tempted to just pass in the message, or pdu,
    # if so, just pluck the command off of it.
    if command.kind_of?(Message)
      command = command.pdu.command
    elsif command.kind_of?(PDU)
      command = command.command
    end

    case command
    when Constants::SNMP_MSG_GET
      get_handler
    when Constants::SNMP_MSG_GETNEXT
      get_next_handler
    when Constants::SNMP_MSG_GETBULK
      get_bulk_handler
    when Constants::SNMP_MSG_SET
      set_handler
    else
      raise "Invalid command type: #{command}"
    end
  end

  [:get, :set, :get_next, :get_bulk].each do |request_type|
    self.class_eval %Q[
      def #{request_type}(&proc)
        self.#{request_type}_handler = proc
      end
    ]
  end
end
end
end
