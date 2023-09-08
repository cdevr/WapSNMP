package main

import (
	"flag"
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
	ifDescr = wapSnmp.MustParseOid(".1.3.6.1.2.1.2.2.1.2")
)

func doGetInterfaces() {
	ws, err := wapSnmp.NewWapSNMP(*target, *community, wapSnmp.SNMPv2c, *timeout, *retries)
	if err != nil {
		log.Fatalf("failed to connect device: %v", err)
	}

	table, err := ws.GetTable(ifDescr)
	if err != nil {
		log.Fatalf("failed to get interfaces name table: %v", err)
	}

	_ = table
}

func main() {
	doGetInterfaces()
}
