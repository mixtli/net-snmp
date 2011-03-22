require 'net/snmp/constants'
module Net
  module SNMP
    include Net::SNMP::Constants

    # Putting this here so there can be one global dispatcher for all sessions.  need to think this through
    REQUESTS = {}

    def self.init(tag="snmp")
      Wrapper.init_snmp(tag)
    end
     
    def self.dispatcher
      Net::SNMP::Session.all_sessions.each do |s|
        s.dispatcher
      end
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
