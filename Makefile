all:gowalk
trapd: utils/trapd.go snmp.go ber.go
	go build utils/trapd.go
gowalk: utils/test.go snmp.go ber.go
	go build utils/test.go
	mv -f test gowalk
clean:
	rm -f trapd gowalk

