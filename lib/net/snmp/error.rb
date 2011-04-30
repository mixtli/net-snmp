module Net
  module SNMP
    class Error < RuntimeError
      attr_accessor :status, :errno, :snmp_err, :snmp_msg
      def initialize(opts = {})
        @status = opts[:status]
        @fiber = opts[:fiber]
        if opts[:session]
          @errno = opts[:session].errno
          @snmp_err = opts[:session].snmp_err
          @snmp_msg = opts[:session].error_message
        end

      end

      def print
        puts "SNMP Error: #{self.class.to_s}"
        puts "message = #{message}"
        puts "status = #{@status}"
        puts "errno = #{@errno}"
        puts "snmp_err = #{@snmp_err}"
        puts "snmp_msg = #{@snmp_msg}"
      end
    end

    class TimeoutError < Error
    end
  end
end

      