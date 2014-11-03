module Net
  module SNMP
    class OID
      extend Debug
      include Debug

      attr_reader :oid, :pointer, :length_pointer
      @oid_size = nil
      @sub_id_bit_width = nil

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

      # Gets the MIB node corresponding to this OID.
      # Note that if this OID represents a MIB node, like '1.3',
      # then `oid.to_s == oid.node.oid.to_s`. However, if there
      # are indices on this oid, then `oid.to_s.start_with?(oid.node.oid.to_s)`
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
        unless @oid_size
          determine_oid_size
        end
        @oid_size
      end

      def self.determine_oid_size
        if Net::SNMP.initialized?
          oid_ptr = FFI::MemoryPointer.new(:ulong, 8)
          length_ptr = FFI::MemoryPointer.new(:size_t, 1)
          length_ptr.write_int(oid_ptr.total)

          Wrapper.read_objid('1.1', oid_ptr, length_ptr)
          oid_str = oid_ptr.read_array_of_uint8(oid_ptr.total).map{|byte| byte.to_s(2).rjust(8, '0') }.join('')

          @oid_size = (oid_str[/10*1/].length - 1) / 8
        else
          @oid_size = FFI::MemoryPointer.new(:ulong).total
          warn "SNMP not initialized\n" + <<-WARNING
            Cannot determine OID sub-id size, assuming common case of sizeof(ulong)
            On this platform, sizeof(ulong) = #{@oid_size} bytes
            To avoid this warning, call `Net::SNMP.init`
            WARNING
        end
      end

      def self.read_pointer(pointer, sub_id_count)
        unless @sub_id_bit_width
          @sub_id_bit_width = OID.oid_size * 8
        end
        pointer.send("read_array_of_uint#{@sub_id_bit_width}", sub_id_count).join('.')
      end
    end
  end
end
