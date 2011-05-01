module Net 
  module SNMP
    class PDU
      # == Represents an SNMP PDU
      #
      #  Wrapper around netsnmp_pdu.
      # * +varbinds+ returns a list of variable bindings
      # * +errstat+ returns the error code.  See constants.rb
      # * +errindex+ returns the index of the varbind causing the error.
      extend Forwardable
      include Net::SNMP::Debug
      attr_accessor :struct, :varbinds, :callback, :command
      def_delegators :struct, :pointer

      # Create a new PDU object.
      # +pdu_type+  The type of the PDU.  For example, Net::SNMP::SNMP_MSG_GET.  See constants.rb
      def initialize(pdu_type)
        @varbinds = []
        case pdu_type
        when FFI::Pointer
          @struct = Wrapper::SnmpPdu.new(pdu_type)
          @command = @struct.command
          v = @struct[:variables]
          if v
            @varbinds << Varbind.from_pointer(v)
          end

          while( !(v = Wrapper::VariableList.new(v).next_variable).null? )
            @varbinds << Varbind.from_pointer(v)
          end
        when Fixnum
          @struct = Wrapper.snmp_pdu_create(pdu_type)
          @command = pdu_type
        else
          raise Error.new, "invalid pdu type"
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

      # Adds a variable binding to the pdu.
      # Options:
      # * +oid+ The SNMP OID
      # * +type+ The data type.  Possible values include Net::SNMP::ASN_OCTET_STR, Net::SNMP::ASN_COUNTER, etc.  See constants.rb
      # * +value+  The value of the varbind.  default is nil.
      def add_varbind(options)
        options[:type] ||= case options[:value]
          when String
            Constants::ASN_OCTET_STR
          when Fixnum
            Constants::ASN_INTEGER
          when Net::SNMP::OID
            Constants::ASN_OBJECT_ID
          when nil
            Constants::ASN_NULL
          else
            raise "Unknown value type"
        end

        value = options[:value]
        value_len = case options[:type]
          when Constants::ASN_NULL
            0
          else
            options[:value].size
        end

        value = case options[:type]
          when Constants::ASN_INTEGER, Constants::ASN_GAUGE, Constants::ASN_COUNTER, Constants::ASN_TIMETICKS, Constants::ASN_UNSIGNED
            new_val = FFI::MemoryPointer.new(:long)
            new_val.write_long(value)
            new_val
          when Constants::ASN_OCTET_STR, Constants::ASN_BIT_STR, Constants::ASN_OPAQUE
            value
          when Constants::ASN_IPADDRESS
            # TODO
          when Constants::ASN_OBJECT_ID
            value.pointer
          when Constants::ASN_NULL
            nil
          else
            if value.respond_to?(:pointer)
              value.pointer
            else
              raise Net::SNMP::Error.new, "Unknown variable type #{options[:type]}"
            end
        end

        oid = options[:oid].kind_of?(OID) ? options[:oid] : OID.new(options[:oid])
        var_ptr = Wrapper.snmp_pdu_add_variable(@struct.pointer, oid.pointer, oid.length_pointer.read_int, options[:type], value, value_len)
        varbind = Varbind.new(var_ptr)
        #Wrapper.print_varbind(varbind.struct)
        varbinds << varbind
      end

      # Returns true if pdu is in error
      def error?
        self.errstat != 0
      end

      # A descriptive error message
      def error_message
        Wrapper::snmp_errstring(self.errstat)
      end

      def print_errors
        puts "errstat = #{self.errstat}, index = #{self.errindex}, message = #{self.error_message}"
      end
      # Free the pdu
      def free
        Wrapper.snmp_free_pdu(@struct.pointer)
      end

      def print
        puts pdu.inspect
      end
    end
  end
end
