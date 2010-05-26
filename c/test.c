#include <stdio.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/types.h>

int main() {
  printf("sizeof(netsnmp_vardata) = %lu\n", sizeof(netsnmp_vardata));
  printf("sizeof(netsnmp_variable_list) = %lu\n", sizeof(netsnmp_variable_list));
  printf("sizeof(netsnmp_session) = %lu\n", sizeof(netsnmp_session));
  printf("sizeof(netsnmp_pdu) = %lu\n", sizeof(netsnmp_pdu));
}
