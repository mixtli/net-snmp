require 'forwardable'
require 'pp'
module Net
  module SNMP
    class Session
      extend Forwardable
      attr_accessor :struct, :callback
      def_delegator :@struct, :pointer
      @sessions = []
      @requests = {}
      class << self
        attr_accessor :sessions, :requests
        def open(options)
          session = new(options)
          if block_given?
            yield session
          end
          session
        end
      end

      def initialize(options)
        options[:community] ||= "public"
        options[:community_len] = options[:community].length
        options[:version] ||= Constants::SNMP_VERSION_1
        @callback = options[:callback]
        @requests = {}
        self.class.sessions << self
        @sess = Wrapper::SnmpSession.new(nil)
        Wrapper.snmp_sess_init(@sess.pointer)
        #options.each_pair {|k,v| ptr.send("#{k}=", v)}
        @sess.community = FFI::MemoryPointer.from_string(options[:community])
        @sess.community_len = options[:community].length
        @sess.peername = FFI::MemoryPointer.from_string(options[:peername])
        @sess.version = case options[:version].to_s
        when '1'
          Constants::SNMP_VERSION_1
        when '2', '2c'
          Constants::SNMP_VERSION_2c
        when '3'
          Constants::SNMP_VERSION_3
        else
          Constants::SNMP_VERSION_1
        end


        if options[:timeout]
          @sess.timeout = options[:timeout] * 1000000
        end
        if options[:retries]
          @sess.retries = options[:retries]
        end


        if @sess.version == Constants::SNMP_VERSION_3
          @sess.securityLevel = options[:security_level] || Constants::SNMP_SEC_LEVEL_NOAUTH

          @sess.securityAuthProto = case options[:auth_protocol]
              when :sha1
                Net::SNMP::OID.new("1.3.6.1.6.3.10.1.1.3").pointer
              when :md5
                Net::SNMP::OID.new("1.3.6.1.6.3.10.1.1.2").pointer
              when nil
                Net::SNMP::OID.new("1.3.6.1.6.3.10.1.1.1").pointer
          end
          
          @sess.securityAuthProtoLen = 10
          @sess.securityAuthKeyLen = Constants::USM_AUTH_KU_LEN

          if options[:context]
            @sess.contextName = FFI::MemoryPointer.from_string(options[:context])
            @sess.contextNameLen = options[:context].length

          end

          if options[:username]
            @sess.securityName = FFI::MemoryPointer.from_string(options[:username])
            @sess.securityNameLen = options[:username].length
          end
          auth_len_ptr = FFI::MemoryPointer.new(:size_t)
          auth_len_ptr.write_int(Constants::USM_AUTH_KU_LEN)
          key_result = Wrapper.generate_Ku(@sess.securityAuthProto, @sess.securityAuthProtoLen, options[:password], options[:password].length, @sess.securityAuthKey, auth_len_ptr)
          @sess.securityAuthKeyLen = auth_len_ptr.read_int
          unless key_result == Constants::SNMPERR_SUCCESS
            Wrapper.snmp_perror("netsnmp")
          end

        end
        
        
        @sess.callback = lambda do |operation, session, reqid, pdu_ptr, magic|
          pdu = Net::SNMP::PDU.new(pdu_ptr)
          run_callbacks(operation, reqid, pdu, magic)
          0
        end

        @struct = Wrapper.snmp_open(@sess.pointer)
        #@handle = Wrapper.snmp_sess_open(@sess.pointer)
        #@struct = Wrapper.snmp_sess_session(@handle)
      end

     

      def run_callbacks(operation, reqid, pdu, magic)
        callback.call(operation, reqid, pdu, magic) if callback
        if self.class.requests[reqid]
          self.class.requests[reqid].call(pdu)
          self.class.requests.delete(reqid)
        end        
      end




#

      def get(oidlist, options = {}, &block)
        pdu = Net::SNMP::PDU.new(Constants::SNMP_MSG_GET)
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid)
        end
        send_pdu(pdu, &block)
      end

      def get_next(oidlist, options = {}, &block)
        pdu = Net::SNMP::PDU.new(Constants::SNMP_MSG_GETNEXT)
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid)
        end
        send_pdu(pdu, &block)
      end

      def get_bulk(oidlist, options = {}, &block)
        pdu = Net::SNMP::PDU.new(Constants::SNMP_MSG_GETBULK)
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid)
        end
        pdu.non_repeaters = options[:non_repeaters] || 0
        pdu.max_repetitions = options[:max_repetitions] || 10
        send_pdu(pdu,&block)
      end



      def set(oidlist, options = {}, &block)
        pdu = Net::SNMP::PDU.new(Constants::SNMP_MSG_SET)
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid[0], :type => oid[1], :value => oid[2])
        end
        send_pdu(pdu, &block)
      end


      # XXX This needs work.  Need to use getbulk for speed, guess maxrepeaters, etc..
      # Also need to figure out how we can tell column names from something like ifTable
      # instead of ifEntry.  Needs to handle errors, there are probably offset problems
      # in cases of bad data, and various other problems.  Also need to add async support.
      # Maybe return a hash with index as key?
      def get_table(table_name, options = {})
        column_names = options[:columns] || Net::SNMP::MIB::Node.get_node(table_name).children.collect {|c| c.label }
        results = []
        oidlist = column_names
        done = false
        catch :break_outer_loop do
          while(result = get_next(oidlist))
            oidlist = []
            row = {}
            result.varbinds.each_with_index do |vb, idx|
              oid = vb.oid
              row[column_names[idx]] = vb.value
              oidlist << oid.label
              if oid.label[0..column_names[idx].length - 1] != column_names[idx]
                throw :break_outer_loop
              end
            end
            results << row
          end
        end
        results
      end
      
      def error(msg)
        Wrapper.snmp_perror("snmp_error")
        Wrapper.snmp_sess_perror( "snmp_error", @sess.pointer)
        #Wrapper.print_session(self.struct)
        raise Net::SNMP::Error.new({:session => self}), msg
      end
      
#      def dispatcher
#          fdset = Net::SNMP::Wrapper.get_fd_set
#          num_fds = FFI::MemoryPointer.new(:int)
#          tval = Net::SNMP::Wrapper::TimeVal.new
#          block = FFI::MemoryPointer.new(:int)
#          block.write_int(0)
#
#          # Note..  for some reason, snmp_sess_select_info changes block to be 1.
#          Net::SNMP::Wrapper.snmp_sess_select_info(@handle, num_fds, fdset, tval.pointer, block )
#          if num_fds.read_int > 0
#            zero = Wrapper::TimeVal.new(:tv_sec => 0, :tv_usec => 0)
#            #Wrapper.print_timeval(zero)
#
#            num_ready = Net::SNMP::Wrapper.select(num_fds.read_int, fdset, nil, nil, zero.pointer)
#            Net::SNMP::Wrapper.snmp_sess_read(@handle, fdset)
#          end
#      end


      private
      def send_pdu(pdu, &block)

        if defined?(EM) && EM.reactor_running? && !block_given?
          Fiber.new {
          f = Fiber.current

          send_pdu pdu do | response |
            f.resume(response)
          end
          }.resume
          Fiber.yield
        else
          if block
            self.class.requests[pdu.reqid] = block
            if (status = Net::SNMP::Wrapper.snmp_send(@struct, pdu.pointer)) == 0
              error("snmp_get async failed")
            end
            nil
          else
            response_ptr = FFI::MemoryPointer.new(:pointer)

            #Net::SNMP::Wrapper.print_session(@struct)
            #Net::SNMP::Wrapper.print_pdu(pdu.struct)
            status = Wrapper.snmp_synch_response(@struct, pdu.pointer, response_ptr)

            if status != 0
              error("snmp_get failed #{status}")
            else
              #Net::SNMP::Wrapper.print_pdu(Net::SNMP::Wrapper::SnmpPdu.new(response_ptr.read_pointer))
              Net::SNMP::PDU.new(response_ptr.read_pointer)
            end
          end
        end

      end
    end
  end
end
