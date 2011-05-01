module Net::SNMP
  module MIB
    class Node
      extend Forwardable
      attr_accessor :struct
      def_delegators :struct, :label, :type, :access, :status
      
      class << self
        def get_node(oid)
          if oid.kind_of?(String)
            oid = OID.new(oid)
          end
          struct = Wrapper.get_tree(oid.pointer, oid.length_pointer.read_int, Wrapper.get_tree_head().pointer)
          new(struct.pointer)
        end
      end
      
      def initialize(arg)
        case arg
        when FFI::Pointer
          @struct = Wrapper::Tree.new(arg)
        else
          raise "invalid type"
        end
      end

      def description
        @struct.description.read_string
      end

      def oid
        return @oid if @oid
        @oid = OID.new(label)
      end

      # actually seems like list is linked backward, so this will retrieve the previous oid numerically
      def next
        return nil unless @struct.next_peer
        self.class.new(@struct.next_peer)
      end
      
      def parent
        return nil unless @struct.parent
        self.class.new(@struct.parent)
      end
      
      def children
        return nil unless @struct.child_list
        child = self.class.new(@struct.child_list)
        children = [child]
        while child = child.next
          children << child
        end
        children.pop
        children.reverse  # For some reason, net-snmp returns everything backwards
      end
      
      def siblings
        parent.children
      end
      
    end
  end
end
