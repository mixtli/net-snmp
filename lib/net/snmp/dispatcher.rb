class Net::SNMP::Dispatcher
  class << self

    # timeout = nil  no block(poll),  timeout = false block forever, timeout = int, block int seconds
#    def poll(timeout = nil)
#        fdset = Net::SNMP::Wrapper.get_fd_set
#        num_fds = FFI::MemoryPointer.new(:int)
#        tv_sec = timeout ? timeout.round : 0
#        tv_usec = timeout ? (timeout - timeout.round) * 1000000 : 0
#        tval = Net::SNMP::Wrapper::TimeVal.new(:tv_sec => tv_sec, :tv_usec => tv_usec)
#        block = FFI::MemoryPointer.new(:int)
#
#        if timeout.nil?
#          block.write_int(0)
#        else
#          block.write_int(1)
#        end
#        #puts "calling snmp_select_info"
#        Net::SNMP::Wrapper.snmp_select_info(num_fds, fdset, tval.pointer, block )
#        #puts "done snmp_select_info."
#        num_ready = 0
#        #puts "block = #{block.read_int}"
#
#        #puts "numready = #{num_fds.read_int}"
#        #puts "tv = #{tval[:tv_sec]} #{tval[:tv_usec]}"
#        #puts "timeout = #{timeout}"
#        tv = (timeout == false ? nil : tval)
#        #puts "calling select"
#        #puts "tv = #{tv.inspect}"
#        #puts "calling select with #{num_fds.read_int}"
#        #num_ready = RubyWrapper.rb_thread_select(num_fds.read_int, fdset, nil, nil, tv)
#        num_ready = Net::SNMP::Wrapper.select(num_fds.read_int, fdset, nil, nil, tv)
#        #puts "done select.  num_ready = #{num_ready}"
#        if num_ready > 0
#          Net::SNMP::Wrapper.snmp_read(fdset)
#        elsif num_ready == 0
#          # timeout.  do something here?  or just return 0?
#        elsif num_ready == -1
#          # error.  check snmp_error?
#        else
#          # uhhh
#        end
#        #puts "done snmp_read"
#        num_ready
#    end


    def poll(timeout = nil)
      #puts "Dispatcher.poll #{Net::SNMP::Session.sessions.size}"
      total = 0
      t = timeout
      t = nil if t == false
      catch :got_data do
        loop do
          Net::SNMP::Session.lock.synchronize {
            Net::SNMP::Session.sessions.each do |k, sess|
              #puts "polling session"
              total += sess.poll(t)
            end
          }
          throw :got_data if total > 0
          throw :got_data unless timeout == false
        end
      end
      #puts "Done Dispatcher.poll"
      total
    end

    def run_loop(options = {})
      if defined?(EM) && EM.reactor_running?
        fiber_loop(options)
      else
        thread_loop(options)
      end
    end

    # You should not pass nil to this as it will peg your cpu
    def thread_loop(options = {})

      timeout = options[:timeout] || 0.1
      sleep_time = options[:sleep] || 0.1
      Thread.new do
        loop do
          #puts "polling"
          num_ready = poll(timeout)
          #puts "num_ready = #{num_ready}"
          if num_ready == 0
            sleep(sleep_time) if sleep_time
          end
        end
      end
    end


    def em_loop(options = {})
      timeout = options[:timeout]
      sleep_time = options[:sleep_time] || 0.1
      myproc = Proc.new do
        EM.next_tick do
          while(true) do
            num_ready = poll(timeout)
            break if num_ready == 0
          end
          EM.add_timer(sleep_time) do
            myproc.call
          end
        end
      end
      myproc.call
    end

    def fiber_loop(options = {})
      timeout = options[:timeout]
      sleep_time = options[:sleep] || 0.1
      Fiber.new {
        loop do
          num_handled = poll(timeout)
          if num_handled == 0
            f = Fiber.current
            EM.add_timer(sleep_time) do
              f.resume
            end
            Fiber.yield
          end
        end
      }.resume(nil)
    end
  end
end