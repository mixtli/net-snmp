class Net::SNMP::Dispatcher
  # A class with convenience methods for polling multiple open sessions
  class << self
    # Loop through all sessions, calling select on each.
    def select(timeout = nil)
      total = 0
      t = timeout
      t = nil if t == false
      catch :got_data do
        loop do
          if Net::SNMP.thread_safe
            Net::SNMP::Session.lock.synchronize {
              Net::SNMP::Session.sessions.each do |k, sess|
                total += sess.select(t)
              end
            }
          else
           Net::SNMP::Session.sessions.each do |k, sess|
              total += sess.select(t)
            end
          end

          throw :got_data if total > 0
          throw :got_data unless timeout == false
        end
      end
      total
    end
    alias :poll :select

    # Start a poller loop.  Behavior depends upon whether
    # you are running under eventmachine and whether fibers
    # are available.
    # +options+
    # * :timeout Number of seconds to block on select. nil effects a poll.  false blocks forever (probably not what you want).
    # * :sleep Number of seconds to sleep if no data is available.  Gives other fibers/threads a chance to run.
    def run_loop(options = {})
      if defined?(EM) && EM.reactor_running?
        if defined?(Fiber)
          fiber_loop(options)
        else
          em_loop(options)
        end
      else
        thread_loop(options)
      end
    end

    # Start a poller loop in a seperate thread.  You
    # should first call Net::SNMP.thread_safe = true.
    # +options+
    # * :timeout Number of seconds to block on select. Will not block other threads.
    # * :sleep Number of seconds to sleep if no data is available.  Allows other threads to run. Default 0.2
    def thread_loop(options = {})
      timeout = options[:timeout] || 0.2
      sleep_time = options[:sleep] || 0.2
      Thread.new do
        loop do
          num_ready = select(timeout)
          if num_ready == 0
            sleep(sleep_time) if sleep_time
          end
        end
      end
    end

    # Start a loop in eventmachine (no fibers)
    # +options+
    # * :sleep Number of seconds to sleep if no data available.  So we don't peg the reactor. Default 0.2
    def em_loop(options = {})
      timeout = options[:timeout]
      sleep_time = options[:sleep] || 0.2
      myproc = Proc.new do
        EM.next_tick do
          while(true) do
            num_ready = select(timeout)
            break if num_ready == 0
          end
          EM.add_timer(sleep_time) do
            myproc.call
          end
        end
      end
      myproc.call
    end

    # Start a loop using eventmachine and fibers
    # +options+
    # * :sleep Number of seconds to sleep if no data available, so we don't peg the reactor. Default 0.2
    def fiber_loop(options = {})
      timeout = options[:timeout]
      sleep_time = options[:sleep] || 0.2
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