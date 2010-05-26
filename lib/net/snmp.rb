require 'net/snmp/constants'
module Net
  module SNMP
    include Net::SNMP::Constants
    REQUESTS = {}


     
    def self.dispatcher
      while REQUESTS.size > 0
        fdset = Net::SNMP::Wrapper.get_fd_set
        fds = FFI::MemoryPointer.new(:int)
        tval = Net::SNMP::Wrapper::TimeVal.new
        block = FFI::MemoryPointer.new(:int)
        block.write_int(1)
        Net::SNMP::Wrapper.snmp_select_info(fds, fdset, tval.pointer, block )
        Net::SNMP::Wrapper.select(fds.read_int, fdset, nil, nil, nil)
        Net::SNMP::Wrapper.snmp_read(fdset)
      end
    end
  end
end
