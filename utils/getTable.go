package main

import (
	"flag"
	"fmt"
	"time"
	WapSNMP "github.com/cdevr/WapSNMP"
)
	//"google3/experimental/users/cde/WapSNMP/WapSNMP"

var target = flag.String("target", "", "The host to connect to")
var community = flag.String("community", "", "The community to use")
var oid_string = flag.String("oid", "", "The oid of the table to get")

func DoGetTable() {
	flag.Parse()

	fmt.Printf("target=%v\ncommunity=%v\noid=%v\n", *target, *community, *oid_string)
	version := WapSNMP.SNMPv2c

	oid, err := WapSNMP.ParseOid(*oid_string)
	if err != nil {
		fmt.Printf("Error parsing oid '%v' : %v", *oid_string, err)
	}

	fmt.Printf("Contacting %v %v %v\n", *target, *community, version)
	wsnmp, err := WapSNMP.NewWapSNMP(*target, *community, version, 2*time.Second, 3)
	if err != nil {
		fmt.Printf("Error creating wsnmp => %v\n", err)
		return
	}
	defer wsnmp.Close()

	table, err := wsnmp.GetTable(oid)
	if err != nil {
		fmt.Printf("Error getting table => %v\n", err)
		return
	}
	for k, v := range table {
		fmt.Printf("%v => %v\n", k, v)
	}
}

func main() {
	DoGetTable()
}
