module Net
  module SNMP
    class PDU
      extend Forwardable
      attr_accessor :struct, :varbinds, :callback
      def_delegators :struct, :reqid, :pointer, :errstat, :errindex, :non_repeaters=

      def initialize(arg)
        @varbinds = []
        case arg
        when FFI::Pointer
          @struct = Wrapper::SnmpPdu.new(arg)
          v = @struct[:variables]
          if v
            @varbinds << Varbind.from_pointer(v)
          end

          while( !(v = Wrapper::VariableList.new(v).next_variable).null? )
            @varbinds << Varbind.from_pointer(v)
          end
        when Fixnum
          @struct = Wrapper.snmp_pdu_create(arg)
        else
          raise "invalid type"
        end
      end

      # For getbulk requests, repeaters and maxreps are stored in errstat and errindex
      def non_repeaters=(nr)
        @struct.errstat = nr
      end
      def non_repeaters
        @struct.errstat
      end
      def max_repetitions=(mr)
        @struct.errindex = mr
      end
      def max_repetitions
        @struct.errindex
      end


      def add_varbind(options)

        options[:type] ||= case options[:value]
        when String
          Constants::ASN_OCTET_STR
        when nil
          Constants::ASN_NULL
        else
          raise "Unknown value type"
        end

        value_len = case options[:value]
        when String
          options[:value].length
        else
          0
        end


        oid = Net::SNMP::OID.new(options[:oid])

        var_ptr = Wrapper.snmp_pdu_add_variable(@struct.pointer, oid.pointer, oid.length_pointer.read_int, options[:type], options[:value], value_len)
        varbind = Varbind.new(var_ptr)
        #Wrapper.print_varbind(varbind.struct)
        varbinds << varbind
      end
      
      def error?
        errstat != 0
      end
      
      def error_message
        Wrapper::snmp_errstring(errstat)
      end

    end
  end
end
