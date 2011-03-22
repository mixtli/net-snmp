module Net
  module SNMP
    class Error < RuntimeError
      #attr :status, :errno, :snmp_err, :snmp_msg
      
      def initialize(opts = {})
        @status = opts[:status]
        if opts[:session]
          errno_ptr = FFI::MemoryPointer.new(:int)
          snmp_err_ptr = FFI::MemoryPointer.new(:int)
          msg_ptr = FFI::MemoryPointer.new(:pointer)
          Wrapper.snmp_error(opts[:session].pointer, errno_ptr, snmp_err_ptr, msg_ptr)

          @errno = errno_ptr.read_int
          @snmp_err = snmp_err_ptr.read_int
          @snmp_msg = msg_ptr.read_pointer.read_string
        end
      end
    end
  end
end

      