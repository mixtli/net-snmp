module Net
  module SNMP
    module Inline
      extend Inliner

      inline do |builder|
        builder.include "sys/select.h"
        builder.include "stdio.h"
        builder.library "netsnmp"
        builder.c %q{
          int snmp_process_callbacks() {
            int fds = 0, block = 1;
            fd_set fdset;
            struct timeval timeout;
            FD_ZERO(&fdset);
            snmp_select_info(&fds, &fdset, &timeout, &block);
            fds = select(fds, &fdset, 0,0, block ? 0 : &timeout);
            if(fds) {
              snmp_read(&fdset);
            } else {
              snmp_timeout();
            }
          }
        }

      end
    end
  end
end
