WapSnmp : SNMP client for golang
--------------------------------
Currently supported operations:
* SNMP v1, v2c Get, GetMultiple, GetNext, GetBulk, Walk
* SNMP V3 Walk
* SNMP V2c/v3 trap receiver with EngineID auto discovery

Not supported yet:
* SNMP Set
* SNMP Informs receiver
* SNMP V3 Get, GetMultiple, GetBulk (these can be easily implemented since SNMP V3 Walk is working)

Compile
--------------------------------
* go build utils/test.go  will build the test program for SNMP v3 walk
* go build utils/trapd.go will build the trapd program, which is able to receive SNMP v2 and v3 traps (you need to configure
users for SNMP v3 traps)

You can run "go test" to perform unit test.

Using the code
---------------------------------
The *_test.go files provide good examples of how to use these functions



