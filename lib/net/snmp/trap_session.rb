module Net
  module SNMP
    class TrapSession < Session
      # == Represents a session for sending SNMP traps
      def initialize(options = {})
        options[:peername] = "#{options[:peername]}:162"
        super(options)
      end

      # Send an SNMPv1 trap
      # +options+
      # * :enterprise The Oid of the enterprise
      # * :trap_type  The generic trap type.
      # * :specific_type The specific trap type
      def trap(options = {})
        pdu = PDU.new(Constants::SNMP_MSG_TRAP)
        options[:enterprise] ||= '1.3.6.1.4.1.3.1.1'  # uh, just send netsnmp enterprise i guess
        pdu.enterprise = OID.new(options[:enterprise])
        pdu.trap_type = options[:trap_type] || 1  # need to check all these defaults
        pdu.specific_type = options[:specific_type] || 0
        pdu.time = 1    # put what here?
        send_pdu(pdu)
        true
      end

      # Send an SNMPv2 trap
      # +options
      # * :oid The Oid of the trap
      # * :varbinds A list of Varbind objects to send with the trap
      def trap_v2(options = {})
        if options[:oid].kind_of?(String)
          options[:oid] = Net::SNMP::OID.new(options[:oid])
        end
        pdu = PDU.new(Constants::SNMP_MSG_TRAP2)
        build_trap_pdu(pdu, options)
        send_pdu(pdu)
      end

      # Send an SNMPv2 inform.  Can accept a callback to execute on confirmation of the inform
      # +options
      # * :oid The OID of the inform
      # * :varbinds A list of Varbind objects to send with the inform
      def inform(options = {}, &callback)
        if options[:oid].kind_of?(String)
          options[:oid] = Net::SNMP::OID.new(options[:oid])
        end
        pdu = PDU.new(Constants::SNMP_MSG_INFORM)
        build_trap_pdu(pdu, options)
        send_pdu(pdu, &callback)
      end

      private
      def build_trap_pdu(pdu, options = {})
        pdu.add_varbind(:oid => OID.new('sysUpTime.0'), :type => Constants::ASN_TIMETICKS, :value => 42)
        pdu.add_varbind(:oid => OID.new('snmpTrapOID.0'), :type => Constants::ASN_OBJECT_ID, :value => options[:oid])
        if options[:varbinds]
          options[:varbinds].each do |vb|
            pdu.add_varbind(vb)
          end
        end
      end
    end
  end
end