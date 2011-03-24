module Net
  module SNMP
    class OID
      def initialize(oid)
        @oid = oid
        @oid_ptr = FFI::MemoryPointer.new(:ulong, Constants::MAX_OID_LEN)
        @oid_len_ptr = FFI::MemoryPointer.new(:size_t)
        @oid_len_ptr.write_int(Constants::MAX_OID_LEN)

        if @oid =~ /^[\d\.]*$/
          if Wrapper.read_objid(@oid, @oid_ptr, @oid_len_ptr) == 0
            Wrapper.snmp_perror(@oid)
          end
        else
          if Wrapper.get_node(@oid, @oid_ptr, @oid_len_ptr) == 0
            Wrapper.snmp_perror(@oid)
          end
        end

      end

      def oid
        @oid
      end

      def c_oid
        @oid_ptr.read_array_of_long(@oid_len_ptr.read_int).join(".")
      end

      def pointer
        @oid_ptr
      end
      def length_pointer
        @oid_len_ptr
      end

    end
  end
end