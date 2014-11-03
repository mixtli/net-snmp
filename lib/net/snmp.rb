require 'net/snmp/constants'
module Net
  module SNMP
    include Net::SNMP::Constants

    @thread_safe = false
    @initialized = false

    def self.init(tag="snmp")
      Wrapper.init_snmp(tag)
      @initialized = true
    end

    def self.thread_safe=(val)
      @thread_safe = val
    end

    def self.thread_safe
      @thread_safe
    end

    def self.initialized?
      @initialized
    end

  end
end
