module Net
  module SNMP
    class Session
      extend Forwardable
      attr_accessor :struct, :callback
      def_delegator :@struct, :pointer
      @@sessions = []
      def initialize(options)
        options[:community] ||= "public"
        options[:community_len] = options[:community].length
        options[:version] ||= Constants::SNMP_VERSION_1
        @callback = options[:callback]
        @requests = {}
        @@sessions << self
        @sess = Wrapper::SnmpSession.new
        Wrapper.snmp_sess_init(@sess.pointer)
        #options.each_pair {|k,v| ptr.send("#{k}=", v)}
        @sess.community = FFI::MemoryPointer.new(options[:community].length + 1)
        @sess.community.write_string(options[:community])
        @sess.community_len = options[:community].length
        puts "options[:peername] = #{options[:peername]}"
        @sess.peername = FFI::MemoryPointer.new(options[:peername].length + 1)
        @sess.peername.write_string(options[:peername])
        puts "peername now #{@sess.peername.read_string}"
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
        
        if @sess.version == Constants::SNMP_VERSION_3
          puts "version 3"
        end
        
        
        @sess.callback = lambda do |operation, session, reqid, pdu_ptr, magic|
          puts "got snmp_session callback"
          pdu = Net::SNMP::PDU.new(pdu_ptr)
          run_callbacks(operation, reqid, pdu, magic)
          0
        end
        @handle = Wrapper.snmp_sess_open(@sess.pointer)
        @struct = Wrapper.snmp_sess_session(@handle)
        puts "final peername = #{@struct.peername.read_string}"
      end

      def self.all_sessions
        @@sessions
      end

      def run_callbacks(operation, reqid, pdu, magic)
        callback.call(operation, reqid, pdu, magic) if callback
        if Net::SNMP::REQUESTS[reqid]
          Net::SNMP::REQUESTS[reqid].call(pdu)
          Net::SNMP::REQUESTS.delete(reqid)
        end        
      end


      def self.open(options)
        session = new(options)
        if block_given?
          yield session
	      end
	      session
      end

      def get(oidlist, options = {}, &block)
        puts "peername inside get #{@struct.peername.read_string}"
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        
        
        pdu = Net::SNMP::PDU.new(Constants::SNMP_MSG_GET)
        
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid)
        end
        
        send_pdu(pdu, &block)

      end
      
      def set(oidlist, options = {}, &block)
        oidlist = [oidlist] unless oidlist.first.kind_of?(Array)
        pdu = Net::SNMP::PDU.new(Constants::SNMP_MSG_SET)
        
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid[0], :type => oid[1], :value => oid[2])
        end
        send_pdu(pdu, &block)


      end
      
      
      def error(msg)
        raise Net::SNMP::Error.new({:session => self}), msg
      end
      
      def dispatcher
          fdset = Net::SNMP::Wrapper.get_fd_set
          fds = FFI::MemoryPointer.new(:int)
          tval = Net::SNMP::Wrapper::TimeVal.new
          block = FFI::MemoryPointer.new(:int)
          block.write_int(1)
          Net::SNMP::Wrapper.snmp_sess_select_info(@handle, fds, fdset, tval.pointer, block )
          if fds.read_int > 0
            zero = Wrapper::TimeVal.new(:tv_sec => 0, :tv_usec => 0)
            num_ready = Net::SNMP::Wrapper.select(fds.read_int, fdset, nil, nil, block.read_int == 1 ? nil : zero.pointer)
            puts "num_ready = #{num_ready}"
            Net::SNMP::Wrapper.snmp_sess_read(@handle, fdset)
          end
      end

      private
      def send_pdu(pdu, &block)
        if block
          REQUESTS[pdu.reqid] = block
          if (status = Net::SNMP::Wrapper.snmp_sess_send(@handle, pdu.pointer)) == 0
            error("snmp_get async failed")
          end
          nil          
        else
          response_ptr = FFI::MemoryPointer.new(:pointer)

          status = Wrapper.snmp_synch_response(@struct.pointer, pdu.pointer, response_ptr)
          if status != 0
            error("snmp_get failed")
          else
            Net::SNMP::PDU.new(response_ptr.read_pointer)
          end
        end
      end
    end
  end
end
