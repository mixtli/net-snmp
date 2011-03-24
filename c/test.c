#include <stdio.h>
#include "string.h"
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/types.h>
#include <net-snmp/library/parse.h>

struct oid {
  char *Name;
  oid Oid[MAX_OID_LEN];
  size_t OidLen;
} oids[] = {
  { "system.sysDescr.0" },
  { "ifDescr.1" },
  { "ifIndex.1" },
  { NULL }
};

int main() {
	struct oid *op = oids;
	init_snmp("snmpdemoapp");
	init_mib();
	test_mib();
    while (op->Name) {
	    op->OidLen = sizeof(op->Oid)/sizeof(op->Oid[0]);

		get_node(op->Name, op->Oid, &op->OidLen);

	    op++;
  	}

	test_synch();


}

int test_mib() {
	struct tree *mytree;
	size_t oidlen;
	int i = 0;
	oid myoid[MAX_OID_LEN];
	snmp_set_save_descriptions(1);

	printf("sizeof(netsnmp_vardata) = %lu\n", sizeof(netsnmp_vardata));
	printf("sizeof(netsnmp_variable_list) = %lu\n", sizeof(netsnmp_variable_list));
	printf("sizeof(netsnmp_session) = %lu\n", sizeof(netsnmp_session));
	printf("sizeof(netsnmp_pdu) = %lu\n", sizeof(netsnmp_pdu));
	oidlen = 100;
	get_node("interfaces.ifNumber.2", myoid, &oidlen);  
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


int test_synch() {
	struct snmp_session ss, *sp;
    struct oid *op;

    snmp_sess_init(&ss);                        /* initialize session */
    ss.version = SNMP_VERSION_2c;
    ss.peername = "127.0.0.1";
    ss.community = "public";
    ss.community_len = strlen(ss.community);
	printf("here\n");
    snmp_synch_setup(&ss);
    if (!(sp = snmp_open(&ss))) {
      snmp_perror("snmp_open");
      return;
    }
	printf("and here\n");
    for (op = oids; op->Name; op++) {
      struct snmp_pdu *req, *resp;
      int status;
      req = snmp_pdu_create(SNMP_MSG_GET);
      snmp_add_null_var(req, op->Oid, op->OidLen);
      status = snmp_synch_response(sp, req, &resp);
	printf("got status %d\n", status);
	printf("oid %s\n", op->Name);
      if (!print_result(status, sp, resp)) break;
      snmp_free_pdu(resp);
    }
    snmp_close(sp);
}



/*
 * simple printing of returned data
 */
int print_result (int status, struct snmp_session *sp, struct snmp_pdu *pdu)
{
  char buf[1024];
  struct variable_list *vp;
  int ix;
  struct timeval now;
  struct timezone tz;
  struct tm *tm;

  gettimeofday(&now, &tz);
  tm = localtime(&now.tv_sec);
  fprintf(stdout, "%.2d:%.2d:%.2d.%.6d ", tm->tm_hour, tm->tm_min, tm->tm_sec,
          now.tv_usec);
  switch (status) {
  case STAT_SUCCESS:
    vp = pdu->variables;
    if (pdu->errstat == SNMP_ERR_NOERROR) {
      while (vp) {
        snprint_variable(buf, sizeof(buf), vp->name, vp->name_length, vp);
        fprintf(stdout, "%s: %s\n", sp->peername, buf);
	vp = vp->next_variable;
      }
    }
    else {
      for (ix = 1; vp && ix != pdu->errindex; vp = vp->next_variable, ix++)
        ;
      if (vp) snprint_objid(buf, sizeof(buf), vp->name, vp->name_length);
      else strcpy(buf, "(none)");
      fprintf(stdout, "%s: %s: %s\n",
      	sp->peername, buf, snmp_errstring(pdu->errstat));
    }
    return 1;
  case STAT_TIMEOUT:
    fprintf(stdout, "%s: Timeout\n", sp->peername);
    return 0;
  case STAT_ERROR:
    snmp_perror(sp->peername);
    return 0;
  }
  return 0;
}