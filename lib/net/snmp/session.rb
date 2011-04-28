require 'thread'
require 'forwardable'
require 'pp'
module Net
  module SNMP
    class Session
      extend Forwardable
      attr_accessor :struct, :callback, :requests, :peername, :community
      attr_reader :version
      def_delegator :@struct, :pointer
      #@sessions = []
      @lock = Mutex.new
      @sessions = {}

      class << self
        attr_accessor :sessions, :lock
        def open(options = {})
          #puts "building session"
          session = new(options)
          @lock.synchronize {
            @sessions[session.sessid] = session
          }
          #puts "done building"
          if block_given?
            #puts "calling block"
            yield session

          end
          session
        end
      end

      def initialize(options = {})
        #puts "in initialize"
        @requests = {}
        @peername = options[:peername] || 'localhost'
        @community = options[:community] || "public"
        options[:community_len] = @community.length
        @version = options[:version] || 1
        options[:version] ||= Constants::SNMP_VERSION_1
        @callback = options[:callback]
        @version = options[:version] || 1
        #self.class.sessions << self
        @sess = Wrapper::SnmpSession.new(nil)
        Wrapper.snmp_sess_init(@sess.pointer)
        #options.each_pair {|k,v| ptr.send("#{k}=", v)}
        @sess.community = FFI::MemoryPointer.from_string(@community)
        @sess.community_len = @community.length
        @sess.peername = FFI::MemoryPointer.from_string(@peername)
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
        # General callback just takes the pdu, calls the session callback if any, then the request specific callback.
        @sess.callback = lambda do |operation, session, reqid, pdu_ptr, magic|
          #puts "callback is #{callback.inspect}"
          #callback.call(operation, reqid, pdu, magic) if callback

          if @requests[reqid]
            pdu = Net::SNMP::PDU.new(pdu_ptr)
            @requests[reqid].call(pdu)
            @requests.delete(reqid)
          end
          0
        end
        @struct = Wrapper.snmp_sess_open(@sess.pointer)
        #@handle = Wrapper.snmp_sess_open(@sess.pointer)
        #@struct = Wrapper.snmp_sess_session(@handle)
      end


      def close
        Net::SNMP::Session.lock.synchronize {
          Wrapper.snmp_sess_close(@struct)
          Net::SNMP::Session.sessions.delete(self.sessid)
        }
      end

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

      def method_missing(m, *args)
        if @struct.respond_to?(m)
          @struct.send(m, *args)
        else
          super
        end
      end


      # XXX This needs work.  Need to use getbulk for speed, guess maxrepeaters, etc..
      # Also need to figure out how we can tell column names from something like ifTable
      # instead of ifEntry.  Needs to handle errors, there are probably offset problems
      # in cases of bad data, and various other problems.  Also need to add async support.
      # Maybe return a hash with index as key?
      def get_table(table_name, options = {})
        column_names = options[:columns] || Net::SNMP::MIB::Node.get_node(table_name).children.collect {|c| c.label }
        results = []

        first_result = get_next(column_names)
        oidlist = []
        good_column_names = []
        row = {}

        first_result.varbinds.each_with_index do |vb, idx|
          oid = vb.oid
          if oid.label[0..column_names[idx].length - 1] == column_names[idx]
            oidlist << oid.label
            good_column_names << column_names[idx]
            row[column_names[idx]] = vb.value
          end
        end
        results << row

        catch :break_main_loop do
          while(result = get_next(oidlist))
            oidlist = []
            row = {}
            result.varbinds.each_with_index do |vb, idx|
              #puts "got #{vb.oid.label} #{vb.value.inspect}, type = #{vb.object_type}"
              row[good_column_names[idx]] = vb.value
              oidlist << vb.oid.label
              if vb.oid.label[0..good_column_names[idx].length - 1] != good_column_names[idx]
                throw :break_main_loop
              end
            end
            results << row
          end
        end
        results
      end
      

      def default_max_repeaters
        # We could do something based on transport here.  25 seems safe
        25
      end

      def get_columns(columns, options = {})
        column_oids = columns.map {|c| Net::SNMP::OID.new(c)}
        options[:max_repetitions] ||= default_max_repeaters / columns.size
        results = {}
        if version == 1
        else
          while(result = get_bulk(columns, options))
            result.varbinds.each do |vb|
              match = column_oids.select {|c| vb.oid.oid =~ /^#{c.oid}/ }
            end
          end

        end
      end

      def error(msg)
        Wrapper.snmp_perror(msg)
        Wrapper.snmp_sess_perror(msg, @sess.pointer)
        
        #Wrapper.print_session(self.struct)
        raise Net::SNMP::Error.new({:session => self}), msg
      end
      

      def trap(options = {})
        pdu = PDU.new(Constants::SNMP_MSG_TRAP)
        options[:enterprise] ||= '1.3.6.1.4.1.3.1.1'  # uh, just send netsnmp enterprise i guess
        pdu.enterprise = OID.new(options[:enterprise])
        pdu.trap_type = options[:trap_type] || 1  # need to check all these defaults
        pdu.specific_type = options[:specific_type] || 0
        pdu.time = 1    # put what here?
        send_pdu(pdu)
        true
      end


      def trap_v2(options = {})
        pdu = PDU.new(Constants::SNMP_MSG_TRAP2)
        build_trap_pdu(pdu, options)
        send_pdu(pdu)
      end

      def inform(options = {}, &block)
        pdu = PDU.new(Constants::SNMP_MSG_INFORM)
        build_trap_pdu(pdu, options)
        send_pdu(pdu, &block)
      end

      def poll(timeout = nil)
        
          fdset = Net::SNMP::Wrapper.get_fd_set
          num_fds = FFI::MemoryPointer.new(:int)
          tv_sec = timeout ? timeout.round : 0
          tv_usec = timeout ? (timeout - timeout.round) * 1000000 : 0
          tval = Net::SNMP::Wrapper::TimeVal.new(:tv_sec => tv_sec, :tv_usec => tv_usec)
          block = FFI::MemoryPointer.new(:int)

          if timeout.nil?
            block.write_int(0)
          else
            block.write_int(1)
          end
          #puts "calling snmp_select_info"
          num = Net::SNMP::Wrapper.snmp_sess_select_info(@struct, num_fds, fdset, tval.pointer, block )
          num_ready = 0
          #puts "block = #{block.read_int}"

          #puts "numready = #{num_fds.read_int}"
          #puts "tv = #{tval[:tv_sec]} #{tval[:tv_usec]}"
          #puts "timeout = #{timeout}"
          tv = (timeout == false ? nil : tval)
          #puts "calling select"
          #puts "tv = #{tv.inspect}"
          #puts "calling select with #{num_fds.read_int}"
          #num_ready = RubyWrapper.rb_thread_select(num_fds.read_int, fdset, nil, nil, tv)
          num_ready = Net::SNMP::Wrapper.select(num_fds.read_int, fdset, nil, nil, tv)
          #puts "done select.  num_ready = #{num_ready}"
          if num_ready > 0
            Net::SNMP::Wrapper.snmp_sess_read(@struct, fdset)
          elsif num_ready == 0
            # timeout.  do something here?  or just return 0?
          elsif num_ready == -1
            # error.  check snmp_error?
          else
            # uhhh
          end
          #puts "done snmp_read"
          num_ready
      end

      private
      def send_pdu(pdu, &block)
        #puts "send_pdu #{Fiber.current.inspect}"
        if defined?(EM) && EM.reactor_running? && !block_given?
          #puts "REACTORRUNNING"
          f = Fiber.current

          send_pdu pdu do | response |
            f.resume(response)
          end
          Fiber.yield
        else
          if block
            @requests[pdu.reqid] = block
            if (status = Net::SNMP::Wrapper.snmp_sess_send(@struct, pdu.pointer)) == 0
              error("snmp_get async failed")
            end
            #pdu.free
            nil
          else
            response_ptr = FFI::MemoryPointer.new(:pointer)
            #Net::SNMP::Wrapper.print_session(@struct)
            #Net::SNMP::Wrapper.print_pdu(pdu.struct)
            #if pdu.command == Net::SNMP::Constants::SNMP_MSG_TRAP
            #  status = Net::SNMP::Wrapper.snmp_sess_send(@struct, pdu.pointer) == 1 ? 0 : 1
            #else
              status = Net::SNMP::Wrapper.snmp_sess_synch_response(@struct, pdu.pointer, response_ptr)
            #end
            #pdu.free  #causing segfaults
            if status != 0
              error("snmp_get failed #{status}")
            else
              #Net::SNMP::Wrapper.print_pdu(Net::SNMP::Wrapper::SnmpPdu.new(response_ptr.read_pointer))
              #if pdu.command == Net::SNMP::Constants::SNMP_MSG_TRAP
                Net::SNMP::PDU.new(response_ptr.read_pointer)
              #else
              #  1
              #end
              
            end
          end
        end
      end

#      def get_entries_cb(pdu, columns, options)
#        cache = {}
#        row_index = nil
#        varbinds = pdu.varbinds.dup
#        while(varbinds.size > 0)
#          row = {}
#          columns.each do |column|
#            vb = varbinds.shift
#            if vb.oid.to_s =~ /#{column.to_s}\.(\d+(:?\.\d+)*)/
#              index = $1
#            else
#              last_entry = true
#              next
#            end
#            row_index = index unless row_index
#            index_cmp = Net::SNMP.oid_lex_cmp(index, row_index)
#            if(index_cmp == 0)
#            end
#          end
#        end
#      end





      def build_trap_pdu(pdu, options = {})
        pdu.add_varbind(:oid => OID.new('sysUpTime'), :type => Constants::ASN_TIMETICKS, :value => 0)
        pdu.add_varbind(:oid => OID.new('snmpTrapOID'), :type => Constants::ASN_OBJECT_ID, :value => options[:oid])
        if options[:varbinds]
          options[:varbinds].each do |vb|
            pdu.add_varbind(vb)
          end
        end
      end


    end
  end
end
