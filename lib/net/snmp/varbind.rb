module Net
  module SNMP
    class Varbind
      # == Represents an SNMP Variable Binding

      attr_accessor :struct
      
      def initialize(ptr = nil)
        @struct = Net::SNMP::Wrapper::VariableList.new(ptr)
      end
      
      def self.from_pointer(ptr)
        new(ptr)
      end

      # Returns the data type of the varbind
      def object_type
        @struct.type
      end
      
      # Returns the OID associated with the varbind
      def oid
        @oid ||= Net::SNMP::OID.new(@struct.name.read_array_of_long(@struct.name_length).join("."))
      end

      # Returns the value of the varbind
      def value
        case object_type
        when Constants::ASN_OCTET_STR, Constants::ASN_OPAQUE
          struct.val[:string].read_string(struct.val_len)
        when Constants::ASN_INTEGER
          struct.val[:integer].read_long
        when Constants::ASN_UINTEGER, Constants::ASN_TIMETICKS,  Constants::ASN_COUNTER, Constants::ASN_GAUGE
          struct.val[:integer].read_ulong
        when Constants::ASN_IPADDRESS
          struct.val[:objid].read_string(struct.val_len).unpack('CCCC').join(".")
        when Constants::ASN_NULL
          nil
          when Constants::ASN_OBJECT_ID
          Net::SNMP::OID.new(struct.val[:objid].read_array_of_long(struct.val_len / 8).join("."))
        when Constants::ASN_COUNTER64
          counter = Wrapper::Counter64.new(struct.val[:counter64])
          counter.high * 2^32 + counter.low
        when Constants::ASN_BIT_STR
          # XXX not sure what to do here.  Is this obsolete?
        when Constants::SNMP_ENDOFMIBVIEW
          :endofmibview
        when Constants::SNMP_NOSUCHOBJECT
          :nosuchobject
        when Constants::SNMP_NOSUCHINSTANCE
          :nosuchinstance
        else
          raise Net::SNMP::Error.new, "Unknown value type #{object_type}"
        end
      end
    end
  end
end
