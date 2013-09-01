module Net
  module SNMP
    module Inline
      extend Inliner

      inline do |builder|
        builder.include "sys/select.h"
        builder.include "net-snmp/net-snmp-config.h"
        builder.include "net-snmp/types.h"
        #builder.include "stdio.h"
        #builder.library "netsnmp"
        builder.c %q{
          int fd_setsize() {
            return(FD_SETSIZE);
          }

        }
        builder.c %q{
          int oid_size() {
            return(sizeof(oid));
          }
        }
      end
    end
  end
end
