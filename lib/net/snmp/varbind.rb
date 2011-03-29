module Net
  module SNMP
    class Varbind
      attr_accessor :struct
      
      def initialize(ptr)
        @struct = Net::SNMP::Wrapper::VariableList.new(ptr)
      end
      
      def self.from_pointer(ptr)
        new(ptr)
      end
      
      def object_type
        @struct.type
      end
      
      def oid
        @oid ||= Net::SNMP::OID.new(@struct.name.read_array_of_long(@struct.name_length).join("."))
      end
      


      def value
        case object_type
        when Constants::ASN_OCTET_STR
          struct.val[:string].read_string(struct.val_len)
        when Constants::ASN_INTEGER, Constants::ASN_COUNTER, Constants::ASN_GAUGE
          struct.val[:integer].read_int
        when Constants::ASN_IPADDRESS
          struct.val[:objid].read_string(struct.val_len).unpack('CCCC').join(".")
        end
      end
    end
  end
end
