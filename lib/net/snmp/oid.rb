module Net
  module SNMP
    class OID
      attr_reader :oid, :pointer, :length_pointer
      @@oid_size = nil
      @@sub_id_bit_width = nil

      def self.from_pointer(ptr, sub_id_count)
        OID.new(OID.read_pointer(ptr, sub_id_count))
      end

      def initialize(oid)
        @oid = oid
        @pointer = FFI::MemoryPointer.new(Net::SNMP::OID.oid_size * Constants::MAX_OID_LEN)
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
        @length_pointer.read_int * Net::SNMP::OID.oid_size
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
        OID.read_pointer(@pointer, length)
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

      def self.oid_size
        unless @@oid_size
          # 32 bytes to parse into... should be plenty
          oid_ptr = FFI::MemoryPointer.new(32)
          length_ptr = FFI::MemoryPointer.new(:size_t, 1)
          length_ptr.write_int(4)

          Wrapper.read_objid('1.1', oid_ptr, length_ptr)
          oid_str = oid_ptr.read_array_of_uint8(8).map{|byte| byte.to_s(2).rjust(9, '0') }.join('')

          # First sub-id is encoded in one byte, even when oid_size is u_long (4 bytes)
          # So, count bytes between first and second sub-id
          @@oid_size = (oid_str[/10*1/].length - 1) / 8
        end
        @@oid_size
      end

      def self.read_pointer(pointer, sub_id_count)
        unless @@sub_id_bit_width
          @@sub_id_bit_width = OID.oid_size * 8
        end
        pointer.send("read_array_of_uint#{@@sub_id_bit_width}", sub_id_count).join('.')
      end
    end
  end
end
