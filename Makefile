all:gowalk goget trapd
trapd: utils/trapd.go snmp.go ber.go
	go build utils/trapd.go
gowalk: utils/gowalk.go snmp.go ber.go
	go build utils/gowalk.go
goget: utils/goget.go snmp.go ber.go
	go build utils/goget.go

#Windows Binary
win_trapd: utils/trapd.go snmp.go ber.go
	GOOS=windows GOARCH=amd64 go build utils/trapd.go
win_gowalk: utils/gowalk.go snmp.go ber.go
	GOOS=windows GOARCH=amd64 go build utils/gowalk.go
win_goget: utils/goget.go snmp.go ber.go
	GOOS=windows GOARCH=amd64 go build utils/goget.go

clean:
	rm -f trapd gowalk goget *.exe

