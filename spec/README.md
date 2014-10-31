Notes
-----

- To test sets, you have to have a local snmpd running with write permissions
- For your local agent, use read community "public" & write community "private"
- A free simulator can be downloaded from [veraxsystems](http://www.veraxsystems.com/en/products/free-snmp-agent-simulator)
  + TODO: This simulator could be used to replace the dependency on test.net-snmp.org

Latest Results
--------------

Generated with `rspec -f d -o spec/spec.txt --no-color`

```
em
  should work in event_machine

snmp errors
  should rescue a timeout error
  should rescue timeout error in a fiber

in fiber
  get should work in a fiber with synchronous calling style
  getnext
  should get using snmpv3

Net::SNMP::MIB::Node
  should get info for sysDescr
  should get parent
  should get node children
  should get siblings
  should get oid
  should get by oid
  should do stuff

Net::SNMP::OID
  should instantiate valid oid with numeric
  should instantiate valid oid with string

synchronous calls
  version 1
    get should succeed
    multiple calls within session should succeed
    get should succeed with multiple oids
    set should succeed
    getnext should succeed
    getbulk should succeed
    getbulk should succeed with multiple oids
    get should return error with invalid oid
    get_table should work
    walk should work
    walk should work with multiple oids
    get_columns should work
    get a value with oid type should work
  version 3
    should get using snmpv3
    should set using snmpv3 (PENDING: No reason given)
    should get using authpriv (PENDING: No reason given)

in a thread
  should get an oid asynchronously in a thread

snmp traps
  should send a v1 trap
  should send a v2 inform (PENDING: still working on it)
  should send v2 trap (PENDING: still working on it)

Net::SNMP::Utility
  should compare oids

Net::SNMP::Wrapper
  wrapper should snmpget synchronously
  wrapper should snmpget asynchronously

Pending:
  synchronous calls version 3 should set using snmpv3
    # No reason given
    # ./spec/sync_spec.rb:117
  synchronous calls version 3 should get using authpriv
    # No reason given
    # ./spec/sync_spec.rb:125
  snmp traps should send a v2 inform
    # still working on it
    # ./spec/trap_spec.rb:14
  snmp traps should send v2 trap
    # still working on it
    # ./spec/trap_spec.rb:26

Finished in 23 seconds (files took 0.42074 seconds to load)
38 examples, 0 failures, 4 pending
```
