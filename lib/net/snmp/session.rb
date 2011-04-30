require 'thread'
require 'forwardable'
require 'pp'
module Net
  module SNMP
    class Session
      # == SNMP Session
      #
      # Provides API for interacting with a host with snmp
      extend Forwardable
      include Net::SNMP::Debug
      attr_accessor :struct, :callback, :requests, :peername, :community
      attr_reader :version
      def_delegator :@struct, :pointer
      #@sessions = []
      @lock = Mutex.new
      @sessions = {}

      class << self
        attr_accessor :sessions, :lock

        # Open a new session.  Accepts a block which yields the session.
        #
        #   Net::SNMP::Session.open(:peername => 'test.net-snmp.org', :community => 'public') do |sess|
        #     pdu = sess.get(["sysDescr.0"])
        #     pdu.print
        #   end
        # Options:
        # * +peername+ - hostname
        # * +community+ - snmp community string.  Default is public
        # * +version+ - snmp version.  Possible values include 1, '2c', and 3. Default is 1.
        # * +timeout+ - snmp timeout in seconds
        # * +retries+ - snmp retries.  default = 5
        # Returns:
        # Net::SNMP::Session

        def open(options = {})
          #puts "building session"
          session = new(options)
          if Net::SNMP::thread_safe
            Net::SNMP::Session.lock.synchronize {
              Net::SNMP::Session.sessions[session.sessid] = session
            }
          else
            Net::SNMP::Session.sessions[session.sessid] = session
          end
          if block_given?
            yield session
          end
          session
        end
      end

      def initialize(options = {})
        #puts "in initialize"
        @timeout = options[:timeout] || 1
        @retries = options[:retries] || 5
        @requests = {}
        @peername = options[:peername] || 'localhost'
        @peername = "#{@peername}:#{options[:port]}" if options[:port]
        @community = options[:community] || "public"
        options[:community_len] = @community.length
        @version = options[:version] || 1
        options[:version] ||= Constants::SNMP_VERSION_1
        @version = options[:version] || 1
        #self.class.sessions << self
        @sess = Wrapper::SnmpSession.new(nil)
        Wrapper.snmp_sess_init(@sess.pointer)
        #options.each_pair {|k,v| ptr.send("#{k}=", v)}
        @sess.community = FFI::MemoryPointer.from_string(@community)
        @sess.community_len = @community.length
        @sess.peername = FFI::MemoryPointer.from_string(@peername)
        #@sess.remote_port = options[:port] || 162
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
        debug "setting timeout = #{@timeout} retries = #{@retries}"
        @sess.timeout = @timeout * 1000000
        @sess.retries = @retries

        if @sess.version == Constants::SNMP_VERSION_3
          @sess.securityLevel = options[:security_level] || Constants::SNMP_SEC_LEVEL_NOAUTH
          @sess.securityAuthProto = case options[:auth_protocol]
              when :sha1
                OID.new("1.3.6.1.6.3.10.1.1.3").pointer
              when :md5
                OID.new("1.3.6.1.6.3.10.1.1.2").pointer
              when nil
                OID.new("1.3.6.1.6.3.10.1.1.1").pointer
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

        @struct = Wrapper.snmp_sess_open(@sess.pointer)
      end


      # Close the snmp session and free associated resources.
      def close
        if Net::SNMP.thread_safe
          self.class.lock.synchronize {
            Wrapper.snmp_sess_close(@struct)
            self.class.sessions.delete(self.sessid)
          }
        else
          Wrapper.snmp_sess_close(@struct)
          self.class.sessions.delete(self.sessid)
        end
      end

      # Issue an SNMP GET Request.
      # See #send_pdu
      def get(oidlist, &block)
        pdu = PDU.new(Constants::SNMP_MSG_GET)
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid)
        end
        send_pdu(pdu, &block)
      end

      # Issue an SNMP GETNEXT Request
      # See #send_pdu
      def get_next(oidlist, &block)
        pdu = PDU.new(Constants::SNMP_MSG_GETNEXT)
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid)
        end
        send_pdu(pdu, &block)
      end

      # Issue an SNMP GETBULK Request
      # See #send_pdu
      def get_bulk(oidlist, options = {}, &block)
        pdu = PDU.new(Constants::SNMP_MSG_GETBULK)
        oidlist = [oidlist] unless oidlist.kind_of?(Array)
        oidlist.each do |oid|
          pdu.add_varbind(:oid => oid)
        end
        pdu.non_repeaters = options[:non_repeaters] || 0
        pdu.max_repetitions = options[:max_repetitions] || 10
        send_pdu(pdu,&block)
      end


      # Issue an SNMP Set Request
      # See #send_pdu
      def set(oidlist, &block)
        pdu = PDU.new(Constants::SNMP_MSG_SET)
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




      def default_max_repeaters
        # We could do something based on transport here.  25 seems safe
        25
      end



      # Raise a NET::SNMP::Error with the session attached
      def error(msg, options = {})
        #Wrapper.snmp_sess_perror(msg, @sess.pointer)
        raise Error.new({:session => self}.merge(options)), msg
      end
      

      # Check the session for SNMP responses from asynchronous SNMP requests
      # This method will check for new responses and call the associated
      # response callbacks.
      # +timeout+  A timeout of nil indicates a poll and will return immediately.
      # A value of false will block until data is available.  Otherwise, pass
      # the number of seconds to block.
      # Returns the number of file descriptors handled.
      def select(timeout = nil)
          fdset = FFI::MemoryPointer.new(:pointer, Net::SNMP::Inline.fd_setsize / 8)
          num_fds = FFI::MemoryPointer.new(:int)
          tv_sec = timeout ? timeout.round : 0
          tv_usec = timeout ? (timeout - timeout.round) * 1000000 : 0
          tval = Wrapper::TimeVal.new(:tv_sec => tv_sec, :tv_usec => tv_usec)
          block = FFI::MemoryPointer.new(:int)
          if timeout.nil?
            block.write_int(0)
          else
            block.write_int(1)
          end

          Wrapper.snmp_sess_select_info(@struct, num_fds, fdset, tval.pointer, block )
          tv = (timeout == false ? nil : tval)
          debug "Calling select #{Time.now}"
          num_ready = FFI::LibC.select(num_fds.read_int, fdset, nil, nil, tv)
          debug "Done select #{Time.now}"
          if num_ready > 0
            Wrapper.snmp_sess_read(@struct, fdset)
          elsif num_ready == 0
            Wrapper.snmp_sess_timeout(@struct)
          elsif num_ready == -1
            # error.  check snmp_error?
            error("select")
          else
            error("wtf is wrong with select?")
          end
          num_ready
      end

      alias :poll :select



      # Send a PDU
      # +pdu+  The Net::SNMP::PDU object to send.  Usually created by Session.get, Session.getnext, etc.
      # +callback+ An optional callback.  It should take two parameters, status and response_pdu.
      # If no +callback+ is given, the call will block until the response is available and will return
      # the response pdu.  If an error occurs, a Net::SNMP::Error will be thrown.
      # If +callback+ is passed, the PDU will be sent and +send_pdu+ will return immediately.  You must
      # then call Session.select to invoke the callback.  This is usually done in some sort of event loop.
      # See Net::SNMP::Dispatcher.
      #
      # If you're running inside eventmachine and have fibers (ruby 1.9, jruby, etc), sychronous calls will
      # actually run asynchronously behind the scenes.  Just run Net::SNMP::Dispatcher.fiber_loop in your
      # reactor.
      #
      #   pdu = Net::SNMP::PDU.new(Constants::SNMP_MSG_GET)
      #   pdu.add_varbind(:oid => 'sysDescr.0')
      #   session.send_pdu(pdu) do |status, pdu|
      #     if status == :success
      #       pdu.print
      #     elsif status == :timeout
      #       puts "Timed Out"
      #     else
      #       puts "A problem occurred"
      #     end
      #   end
      #   session.select(false)  #block until data is ready.  Callback will be called.
      #   begin
      #     result = session.send_pdu(pdu)
      #     puts result.inspect
      #   rescue Net::SNMP::Error => e
      #     puts e.message
      #   end
      def send_pdu(pdu, &callback)
        #puts "send_pdu #{Fiber.current.inspect}"
        if block_given?
          @requests[pdu.reqid] = callback
          puts "calling async_send"
          if Wrapper.snmp_sess_async_send(@struct, pdu.pointer, sess_callback, nil) == 0
            error("snmp_get async failed")
          end
          #pdu.free
          nil
        else
          if defined?(EM) && EM.reactor_running? && defined?(Fiber)
            f = Fiber.current
            send_pdu pdu do | op, response_pdu |
              f.resume([op, response_pdu])
            end
            op, result = Fiber.yield
            case op
              when :timeout
                raise TimeoutError.new, "timeout"
              when :send_failed
                error "send failed"
              when :success
                result
              when :connect, :disconnect
                nil   #does this ever happen?
              else
                error "unknown operation #{op}"
            end
          else
            response_ptr = FFI::MemoryPointer.new(:pointer)
            if [Constants::SNMP_MSG_TRAP, Constants::SNMP_MSG_TRAP2].include?(pdu.command)
              status = Wrapper.snmp_sess_send(@struct, pdu.pointer)
              if status == 0
                error("snmp_sess_send")
              end
            else
              status = Wrapper.snmp_sess_synch_response(@struct, pdu.pointer, response_ptr)
              unless status == Constants::STAT_SUCCESS
                error("snmp_sess_synch_response", :status => status)
              end
            end
            if [Constants::SNMP_MSG_TRAP, Constants::SNMP_MSG_TRAP2].include?(pdu.command)
              1
            else
              PDU.new(response_ptr.read_pointer)
            end
          end
        end
      end

      def errno
        get_error
        @errno
      end

      # The SNMP Session error code
      def snmp_err
        get_error
        @snmp_err
      end

      # The SNMP Session error message
      def error_message
        get_error
        @snmp_msg
      end
      
      private
      def sess_callback
        @sess_callback ||= FFI::Function.new(:int, [:int, :pointer, :int, :pointer, :pointer]) do |operation, session, reqid, pdu_ptr, magic|
          #puts "in callback #{operation.inspect} #{session.inspect}"
          op = case operation
            when Constants::NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE
              :success
            when Constants::NETSNMP_CALLBACK_OP_TIMED_OUT
              :timeout
            when Constants::NETSNMP_CALLBACK_OP_SEND_FAILED
              :send_failed
            when Constants::NETSNMP_CALLBACK_OP_CONNECT
              :connect
            when Constants::NETSNMP_CALLBACK_OP_DISCONNECT
              :disconnect
            else
              error "Invalid PDU Operation"
          end

          if @requests[reqid]
            pdu = PDU.new(pdu_ptr)
            callback_return = @requests[reqid].call(op, pdu)
            @requests.delete(reqid)
            callback_return == false ? 0 : 1 #if callback returns false (failure), pass it on.  otherwise return 1 (success)
          else
            0# Do what here?  Can this happen?  Maybe request timed out and was deleted?
          end
        end
      end
      def get_error
          errno_ptr = FFI::MemoryPointer.new(:int)
          snmp_err_ptr = FFI::MemoryPointer.new(:int)
          msg_ptr = FFI::MemoryPointer.new(:pointer)
          Wrapper.snmp_sess_error(@struct.pointer, errno_ptr, snmp_err_ptr, msg_ptr)
          @errno = errno_ptr.read_int
          @snmp_err = snmp_err_ptr.read_int
          @snmp_msg = msg_ptr.read_pointer.read_string
      end

      public
      # XXX This needs work.  Need to use getbulk for speed, guess maxrepeaters, etc..
      # Also need to figure out how we can tell column names from something like ifTable
      # instead of ifEntry.  Needs to handle errors, there are probably offset problems
      # in cases of bad data, and various other problems.  Also need to add async support.
      # Maybe return a hash with index as key?
      def get_table(table_name, options = {})
        column_names = options[:columns] || MIB::Node.get_node(table_name).children.collect {|c| c.label }
        results = []

#        repeat_count = if @version.to_s == '1' || options[:no_getbulk]
#            1
#          elsif options[:repeat_count]
#            options[:repeat_count]
#          else
#            (1000 / 36 / (column_names.size + 1)).to_i
#        end
#
#        res = if @version.to_s != '1' && !options[:no_getbulk]
#          get_bulk(column_names, :max_repetitions => repeat_count)
#        else
#          get_next(column_names)
#        end


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
    end
  end
end


