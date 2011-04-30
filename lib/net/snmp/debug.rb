module Net
  module SNMP
    module Debug
      @@debug = false

      def self.debug=(val)
        @@debug = val
      end

      def debug(msg)
        if @@debug
          puts msg
        end
      end
    end
  end
end