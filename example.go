package wapsnmp

import (
	"fmt"
	"time"
)

func doGetTableTest(target string) {
	community := "public"
	version := SNMPv2c

	oid := MustParseOid(".1.3.6.1.4.1.2636.3.2.3.1.20")

	fmt.Printf("Contacting %v %v %v\n", target, community, version)
	wsnmp, err := NewWapSNMP(target, community, version, 2*time.Second, 5)
	defer wsnmp.Close()
	if err != nil {
		fmt.Printf("Error creating wsnmp => %v\n", wsnmp)
		return
	}

	table, err := wsnmp.GetTable(oid)
	if err != nil {
		fmt.Printf("Error getting table => %v\n", wsnmp)
		return
	}
	for k, v := range table {
		fmt.Printf("%v => %v\n", k, v)
	}
}

func doWalkTest(target string) {
	community := "public"
	version := SNMPv2c

	oid := MustParseOid(".1.3.6.1.2.1")

	fmt.Printf("Contacting %v %v %v\n", target, community, version)
	wsnmp, err := NewWapSNMP(target, community, version, 2*time.Second, 5)
	defer wsnmp.Close()
	if err != nil {
		fmt.Printf("Error creating wsnmp => %v\n", wsnmp)
		return
	}
	defer wsnmp.Close()
	for {
		results, err := wsnmp.GetBulk(oid, 50)
		if err != nil {
			fmt.Printf("GetBulk error => %v\n", err)
			return
		}
		for o, v := range results {
			fmt.Printf("%v => %v\n", o, v)

			oid = MustParseOid(o)
		}
	}
}

func doGetTest(target string) {
	community := "public"
	version := SNMPv2c

	oids := []Oid{
		MustParseOid(".1.3.6.1.2.1.1.1.0"),
		MustParseOid(".1.3.6.1.2.1.1.2.0"),
		MustParseOid(".1.3.6.1.2.1.2.1.0"),
	}

	wsnmp, err := NewWapSNMP(target, community, version, 2*time.Second, 5)
	defer wsnmp.Close()
	if err != nil {
		fmt.Printf("Error creating wsnmp => %v\n", wsnmp)
		return
	}

	for _, oid := range oids {
		val, err := wsnmp.Get(oid)
		fmt.Printf("Getting %v\n", oid)
		if err != nil {
			fmt.Printf("Get error => %v\n", wsnmp)
			return
		}
		fmt.Printf("Get(%v, %v, %v, %v) => %v\n", target, community, version, oid, val)
	}
}
