module Net
  module SNMP
    module Inline
      extend Inliner

      inline do |builder|
        builder.include "sys/select.h"
        #builder.include "stdio.h"
        #builder.library "netsnmp"
        builder.c %q{
          int fd_setsize() {
            return(FD_SETSIZE);
          }
        }

      end
    end
  end
end
