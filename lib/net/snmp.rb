require 'net/snmp/constants'
module Net
  module SNMP
    include Net::SNMP::Constants
    @thread_safe = false
    def self.init(tag="snmp")
      Wrapper.init_snmp(tag)
    end

    def self.thread_safe=(val)
      @thread_safe = val
    end

    def self.thread_safe
      @thread_safe
    end

  end
end
