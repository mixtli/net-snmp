module Net
  module SNMP
    module MIB
      def self.init
        Wrapper.init_mib
      end
      
      def self.read_all_mibs
        Wrapper.read_all_mibs
      end
      
      def self.get_node(oid)
        Node.get_node(oid)
      end


      
    end
  end
end
