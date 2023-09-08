package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	wapSnmp "github.com/cdevr/WapSNMP"
)

var target = flag.String("target", "", "The host to connect to")
var community = flag.String("community", "public", "The community to use")
var timeout = flag.Duration("timeout", 2*time.Second, "timeout for packets")
var retries = flag.Int("retries", 5, "how many times to retry sending a packet before giving up")
var refresh = flag.Duration("refresh", 3*time.Second, "how often to refresh")

var (
	sysDescrOid = wapSnmp.MustParseOid(".1.3.6.1.2.1.1.1")
	ifDescrOid  = wapSnmp.MustParseOid(".1.3.6.1.2.1.2.2.1.2")
)

func doGetInterfaces() {
	ws, err := wapSnmp.NewWapSNMP(*target, *community, wapSnmp.SNMPv2c, *timeout, *retries)
	if err != nil {
		log.Fatalf("failed to connect device: %v", err)
	}

	sysDescr, err := ws.Get(sysDescrOid)
	if err != nil {
		log.Fatalf("failed to get system description from device: %v", err)
	}

	table, err := ws.GetTable(ifDescrOid)
	if err != nil {
		log.Fatalf("failed to get interfaces name table: %v", err)
	}

	fmt.Printf("system name: %q", sysDescr)
	for k, v := range table {
		fmt.Printf("%v => %v", k, v)
	}
}

func main() {
	doGetInterfaces()
}
