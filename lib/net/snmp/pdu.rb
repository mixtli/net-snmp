module Net
  module SNMP
    class PDU
      extend Forwardable
      attr_accessor :struct, :varbinds, :callback
      def_delegators :struct, :reqid, :pointer, :errstat, :errindex

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

        oid_ptr = FFI::MemoryPointer.new(:ulong, Constants::MAX_OID_LEN)
        oid_len_ptr = FFI::MemoryPointer.new(:size_t)
        oid_len_ptr.write_int(Constants::MAX_OID_LEN)

        if !Wrapper.snmp_parse_oid(options[:oid], oid_ptr, oid_len_ptr)
          Wrapper.snmp_perror(options[:oid])
        end
        #var_ptr = Wrapper.snmp_add_null_var(@struct.pointer, oid_ptr, oid_len_ptr.read_int)
        var_ptr = Wrapper.snmp_pdu_add_variable(@struct.pointer, oid_ptr, oid_len_ptr.read_int, options[:type], options[:value], value_len)
        varbinds << Varbind.new(var_ptr)
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
