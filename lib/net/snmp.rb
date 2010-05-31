require 'net/snmp/constants'
module Net
  module SNMP
    include Net::SNMP::Constants
    REQUESTS = {}

    def self.init(tag="snmp")
      Wrapper.init_snmp(tag)
    end
     
    def self.dispatcher
      puts "in dispatcher"
      #while REQUESTS.size > 0
        puts REQUESTS.inspect
        fdset = Net::SNMP::Wrapper.get_fd_set
        fds = FFI::MemoryPointer.new(:int)
        tval = Net::SNMP::Wrapper::TimeVal.new
        block = FFI::MemoryPointer.new(:int)
        block.write_int(1)
        Net::SNMP::Wrapper.snmp_select_info(fds, fdset, tval.pointer, block )
        puts "selecting"
        if fds.read_int > 0
          puts "snmp_select returned #{fds.read_int}"
          zero = Wrapper::TimeVal.new(:tv_sec => 0, :tv_usec => 0)
          puts "block is #{block.read_int}"
          num_ready = Net::SNMP::Wrapper.select(fds.read_int, fdset, nil, nil, block.read_int == 1 ? nil : zero.pointer)
          puts "got #{num_ready} descriptors"
          Net::SNMP::Wrapper.snmp_read(fdset)
        end
      #end
      puts "exited dispatcher"
    end

    def self._get_oid(name)
      oid_ptr = FFI::MemoryPointer.new(:ulong, Constants::MAX_OID_LEN)
      oid_len_ptr = FFI::MemoryPointer.new(:size_t)
      oid_len_ptr.write_int(Constants::MAX_OID_LEN)

      if !Wrapper.snmp_parse_oid(name, oid_ptr, oid_len_ptr)
        Wrapper.snmp_perror(name)
      end
      [oid_ptr, oid_len_ptr]
    end

    def self.get_oid(name)
      oid_ptr, oid_len_ptr = _get_oid(name)
      oid_ptr.read_array_of_long(oid_len_ptr.read_int).join(".")
    end


  end
end
