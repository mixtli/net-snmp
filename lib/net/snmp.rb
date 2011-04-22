require 'net/snmp/constants'
module Net
  module SNMP
    include Net::SNMP::Constants


    def self.init(tag="snmp")
      Wrapper.init_snmp(tag)
    end

    # timeout = nil  no block(poll),  timeout = false block forever, timeout = int, block int seconds
    def self.dispatcher(timeout = nil)
        fdset = Net::SNMP::Wrapper.get_fd_set
        num_fds = FFI::MemoryPointer.new(:int)
        tv_sec = timeout || 0
        tval = Net::SNMP::Wrapper::TimeVal.new(:tv_sec => tv_sec, :tv_usec => 0)
        block = FFI::MemoryPointer.new(:int)

        if timeout.nil?
          block.write_int(0)
        else
          block.write_int(1)
        end
        #puts "calling snmp_select_info"
        Net::SNMP::Wrapper.snmp_select_info(num_fds, fdset, tval.pointer, block )
        #puts "done snmp_select_info."
        num_ready = 0
        #puts "block = #{block.read_int}"

        #puts "numready = #{num_fds.read_int}"
        #puts "tv = #{tval[:tv_sec]} #{tval[:tv_usec]}"
        if num_fds.read_int > 0
          tv = timeout == false ? nil : tval
          #puts "calling select"
          num_ready = Net::SNMP::Wrapper.select(num_fds.read_int, fdset, nil, nil, tv)
          #puts "done select.  num_ready = #{num_ready}"
          Net::SNMP::Wrapper.snmp_read(fdset)
        else
        end
        num_ready
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
