#include <stdio.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/types.h>
#include <net-snmp/library/parse.h>
int main() {
  struct tree *mytree;
  size_t oidlen;
  int i = 0;
  oid myoid[MAX_OID_LEN];
  init_snmp("snmpdemoapp");
  init_mib();
                    snmp_set_save_descriptions(1);
                        
  printf("sizeof(netsnmp_vardata) = %lu\n", sizeof(netsnmp_vardata));
  printf("sizeof(netsnmp_variable_list) = %lu\n", sizeof(netsnmp_variable_list));
  printf("sizeof(netsnmp_session) = %lu\n", sizeof(netsnmp_session));
  printf("sizeof(netsnmp_pdu) = %lu\n", sizeof(netsnmp_pdu));
  oidlen = 100;
  get_node("system.sysDescr", myoid, &oidlen);  
  printf("oidlen = %lu\n", oidlen);
  for(i=0;i < oidlen; i++) {
    printf("%lu\n", myoid[i]);
  }
  mytree = get_tree(myoid, oidlen, get_tree_head());
  printf("label = %s\n", mytree->label);
  printf("description = %s\n", mytree->description);
  print_description(myoid, oidlen, 200);
                
  print_mib_tree(stdout, mytree, 1000);
}
