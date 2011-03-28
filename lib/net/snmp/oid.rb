module Net
  module SNMP
    class OID
      attr_reader :oid, :pointer, :length_pointer
      def initialize(oid)
        @oid = oid
        @pointer = FFI::MemoryPointer.new(:ulong, Constants::MAX_OID_LEN)
        @length_pointer = FFI::MemoryPointer.new(:size_t)
        @length_pointer.write_int(Constants::MAX_OID_LEN)

        if @oid =~ /^[\d\.]*$/
          if Wrapper.read_objid(@oid, @pointer, @length_pointer) == 0
            Wrapper.snmp_perror(@oid)
          end
        else
          if Wrapper.get_node(@oid, @pointer, @length_pointer) == 0
            Wrapper.snmp_perror(@oid)
          end
          @oid = c_oid
        end

      end

      def oid
        @oid
      end

      def name
        @oid
      end

      def c_oid
        @pointer.read_array_of_long(length_pointer.read_int).join(".")
      end

      def node
        MIB::Node.get_node(oid)
      end

      def index
        oid.sub(node.oid.name + ".","")
      end

      def label
        node.label + "." + index
      end
   
    end
  end
end