module Net 
  module SNMP
    class PDU
      extend Forwardable
      attr_accessor :struct, :varbinds, :callback
      def_delegators :struct, :pointer

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
      def enterprise=(e_oid)
        @enterprise = e_oid
        @struct.enterprise = e_oid.pointer
        @struct.enterprise_length = e_oid.size
      end
      def enterprise
        @enterprise
      end
      
      def agent_addr=(addr)
        @struct.agent_addr = addr.split('.').pack("CCCC")
        @agent_addr = addr
      end

      def agent_addr
        @agent_addr
      end


      def method_missing(m, *args)
        if @struct.respond_to?(m)
          @struct.send(m, *args)
        else
          super
        end
      end

      def add_varbind(options)
        options[:type] ||= case options[:value]
          when String
            Constants::ASN_OCTET_STR
          when Fixnum
            Constants::ASN_INTEGER
          when nil
            Constants::ASN_NULL
          else
            raise "Unknown value type"
        end

        value = options[:value]
        value_len = case options[:value]
          when String
            options[:value].length
          when nil
            0
          else
            options[:value].size
        end


        if value.respond_to?(:pointer)
          value = value.pointer
        end

        #oid = options[:oid].kind_of?(Net::SNMP::OID) ? options[:oid] : Net::SNMP::OID.new(options[:oid])
        oid = Net::SNMP::OID.new(options[:oid])
        var_ptr = Wrapper.snmp_pdu_add_variable(@struct.pointer, oid.pointer, oid.length_pointer.read_int, options[:type], value, value_len)
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

      def free
        Wrapper.snmp_free_pdu(@struct.pointer)
      end
    end
  end
end
