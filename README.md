WapSnmp : SNMP client for golang
--------------------------------
Currently supported operations:
* SNMP v1/v2c/v3 trap receiver with V3 EngineID auto discovery
* SNMP v1/v2c Get, GetMultiple, GetNext, GetBulk, Walk
* SNMP V3     Get, Walk, GetNext

Compile
--------------------------------
make 

This will compile the following binaries:
* goget  : get single SNMP mib using SNMP v3
* gowalk : walk SNMP mibs using SNMP v3
* trapd  : this program is able to receive SNMP v2 and v3 traps (you need to configure users for SNMP v3 traps)

You can run "go test" to perform unit test.

Using the code
---------------------------------
* The *_test.go files provide good examples of how to use these functions
* file uder utils/ contain the main entry to the utility program. Then look at example.go and snmp.go to see how it works.

Not supported yet:
------------------
* SNMP Informs receiver
* SNMP v3 GetMultiple, GetBulk (these can be easily implemented since SNMP v3 Walk/Get/GetNext is working)




