module Net
  module SNMP
    module Inline
      def self.fd_setsize
        64 # For now.... need a way to do this without inline compilation
      end
    end
  end
end
