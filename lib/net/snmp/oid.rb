module Net
  module SNMP
    class OID
      attr_reader :oid, :pointer, :length_pointer

      def from_pointer(ptr, len)
        
      end
      def initialize(oid)
        @oid = oid
        @pointer = FFI::MemoryPointer.new(Net::SNMP::Inline.oid_size * Constants::MAX_OID_LEN)
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
          @oid = to_s
        end

      end

      def size
        @length_pointer.read_int * Net::SNMP::Inline.oid_size 
      end

      def length
        @length_pointer.read_int
      end
      def oid
        @oid
      end

      def name
        @oid
      end

      def to_s
        if Net::SNMP::Inline.oid_size == 8
          @pointer.read_array_of_ulong(length).join(".")
        else
          @pointer.read_array_of_uint(length).join(".")
        end
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
   
      def <=>(o)
        a = self._packed
        b = o._packed
        a <=> b
      end

      def _packed
        i = self.to_s.dup
        i.sub!(/^\./,'')
        i.gsub!(/ /, '.0')
        i.replace(i.split('.').map(&:to_i).pack('N*'))
      end

      def parent_of?(o)
        o.to_s =~ /^#{self.to_s}\./
      end
    end
  end
end
