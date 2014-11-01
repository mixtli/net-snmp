module Net::SNMP
  module MIB
    class Node
      include Debug
      extend Forwardable
      attr_accessor :struct
      def_delegators :struct, :label, :type, :access, :status

      class << self
        include Debug
        def get_node(oid)
          if oid.kind_of?(String)
            oid = OID.new(oid)
          end
          struct = Wrapper.get_tree(oid.pointer, oid.length_pointer.read_int, Wrapper.get_tree_head().pointer)
          warn "OID #{oid.to_s} not found in MIB" if struct.parent.null? && oid.to_s != '1'
          new(struct.pointer)
        end
      end

      def initialize(arg)
        @oid = nil
        case arg
        when Wrapper::Tree
          @struct = arg
        when FFI::Pointer
          @struct = Wrapper::Tree.new(arg)
        else
          raise "invalid type"
        end
      end

      def description
        if @struct.description.null?
          nil
        else
          @struct.description.read_string
        end
      end

      def oid
        return @oid if @oid
        @oid = OID.new(label)
      end

      # actually seems like list is linked backward, so this will retrieve the previous oid numerically
      def next
        return nil if @struct.next.null?
        self.class.new(@struct.next)
      end

      def next_peer
        return nil if @struct.next_peer.null?
        self.class.new(@struct.next_peer)
      end

      def parent
        return nil if @struct.parent.null?
        self.class.new(@struct.parent)
      end

      def children
        return to_enum __method__ unless block_given?
        return if @struct.child_list.null?
        child = self.class.new(@struct.child_list)
        yield child
        while child = child.next_peer
          yield child
        end
      end

      def peers
        return [] if oid.to_s == '1'
        parent.children.reject { |n| n.oid.to_s == oid.to_s }
      end
      alias siblings peers

      def enums
        return to_enum __method__ unless block_given?
        enum = struct.enums
        while !enum.null?
          yield({value: enum.value, label: enum.label.read_string})
          enum = enum.next
        end
      end

    end
  end
end
