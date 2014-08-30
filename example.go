package wapsnmp

import (
	"fmt"
	"time"
)

func DoGetTableTest(target string) {
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

func DoWalkTest(target string) {
	community := "monitorhcm"
	version := SNMPv2c

	oid := MustParseOid(".1.3.6.1.2.1.1")
	oid0 := oid;

	fmt.Printf("Contacting %v %v %v\n", target, community, version)
	wsnmp, err := NewWapSNMP(target, community, version, 2*time.Second, 5)
	if err != nil {
		fmt.Printf("Error creating wsnmp => %v\n", wsnmp)
		return
	}
	defer wsnmp.Close()
	for {
		    result_oid, val, err := wsnmp.GetNext(oid)
		    if err != nil {
		      fmt.Printf("GetNext error => %v\n", err)
		      return
		    }
		    fmt.Printf("GetNext(%v, %v, %v, %v) => %s, %v\n", target, community, version, oid, result_oid, val)
		    oid = *result_oid
			if ! oid.Within(oid0) {
				break;
			}
	}
}

func DoWalkTestV3(target string, oidstr,username, authAlg, authKey, privAlg, privKey string) {
	oid := MustParseOid(oidstr)
	oid0 := oid;

	fmt.Printf("Contacting %v using SNMP v3\n", target)
	wsnmp, err := NewWapSNMPv3(target,  username, authAlg, authKey, privAlg, privKey, 2*time.Second, 2)
	if err != nil {
		fmt.Printf("Error creating wsnmp => %v\n", wsnmp)
		return
	}
	defer wsnmp.Close()
	wsnmp.Discover();
	for {
		    result_oid, val, err := wsnmp.GetNextV3(oid)
		    if err != nil {
		      fmt.Printf("GetNext error => %v\n", err)
		      return
		    }
		    fmt.Printf("GetNext(%v, %v) => %s, %v\n", target, oid, result_oid, val)

		    oid = *result_oid
			if ! oid.Within(oid0) {
				break;
			}
	}
}

func DoGetTest(target string) {
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

func DoGetTestV3(target string, oidstr,username, authAlg, authKey, privAlg, privKey string) {
	oid := MustParseOid(oidstr)

	fmt.Printf("Contacting %v using SNMP v3\n", target)
	wsnmp, err := NewWapSNMPv3(target,  username, authAlg, authKey, privAlg, privKey, 2*time.Second, 2)
	if err != nil {
		fmt.Printf("Error creating wsnmp => %v\n", wsnmp)
		return
	}
	defer wsnmp.Close()
	wsnmp.Discover();

	val, err := wsnmp.GetV3(oid)
	if err != nil {
		fmt.Printf("GetV3 error => %v\n", err)
		return
	}
	fmt.Printf("GetV3(%v) => %v\n", oid , val)
}

