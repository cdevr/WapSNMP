trapd: utils/trapd.go snmp.go
	go build utils/trapd.go
clean:
	rm -f trapd

