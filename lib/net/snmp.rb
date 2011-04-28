require 'net/snmp/constants'
module Net
  module SNMP
    include Net::SNMP::Constants


    def self.init(tag="snmp")
      Wrapper.init_snmp(tag)
    end





  end
end
