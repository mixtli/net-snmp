%module snmp_api

%{
module SNMP
  extend FFI::Library
%}

#define NETSNMP_IMPORT extern

%include snmp_api.h



%{
end
%}
