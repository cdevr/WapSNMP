package wapsnmp

import (
	"fmt"
	"math/rand" // Needed to set Seed, so a consistent request ID will be chosen.
	"testing"
	"time"
	"encoding/hex"
)

func ExampleGetTable() {
	target := "some_host"
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

func ExampleGetBulk() {
	target := "some_host"
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
		/*  Old version without GETBULK
		    result_oid, val, err := wsnmp.GetNext(oid)
		    if err != nil {
		      fmt.Printf("GetNext error => %v\n", err)
		      return
		    }
		    fmt.Printf("GetNext(%v, %v, %v, %v) => %s, %v\n", target, community, version, oid, result_oid, val)
		    oid = *result_oid
		*/
	}
}

func ExampleGet() {
	target := "some_host"
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
			fmt.Printf("Get error => %v\n", err)
			return
		}
		fmt.Printf("Get(%v, %v, %v, %v) => %v\n", target, community, version, oid, val)
	}
}

func TestGet(t *testing.T) {
	rand.Seed(0)


	target := "magic_host"
	community := "[R0_C@cti!]"
	version := SNMPv2c

	oid := MustParseOid("1.3.6.1.2.1.1.3.0")

	udpStub := NewUdpStub(t)
	defer udpStub.CheckClosed()
	// Expect a UDP SNMP GET packet.
	udpStub.Expect("302e020101040b5b52305f4340637469215da01c020478fc2ffa020100020100300e300c06082b060102010103000500").AndRespond([]string{"3032020101040b5b52305f4340637469215da220020421182cd70201000201003012301006082b06010201010300430404926fa4"})

	wsnmp := NewWapSNMPOnConn(target, community, version, 2*time.Second, 5, udpStub)
	//wsnmp, err := NewWapSNMP(target, community, version, 2*time.Second, 5)
	defer wsnmp.Close()
	val, err := wsnmp.Get(oid)

	if err != nil {
		t.Errorf("Error testing to get a value : %v.", err)
	}

	if val != time.Duration(76705700)*10*time.Millisecond {
		t.Errorf("Received wrong value : %v", val)
	}

}

func TestTrapV2(t *testing.T) {
	rand.Seed(0)
	target := "magic_host"
	community := "public"
	version := SNMPv2c

	//oid := MustParseOid("1.2.3.4.0")
	udpStub := NewUdpStub(t)
	defer udpStub.CheckClosed()
	wsnmp := NewWapSNMPOnConn(target, community, version, 2*time.Second, 5, udpStub)
	defer wsnmp.Close()

	packet,err:=hex.DecodeString("304302010104067075626c6963a73602047cd94c540201000201003028301006082b0601020101030043043aa3e6303014060a2b06010603010104010006062b0601020100")
	if err != nil {
		t.Fatalf("Error while decoding trap packet : '%v'", err)
	}

	val, err := wsnmp.ParseTrap(packet)
	if err != nil {
		t.Errorf("Error testing parsing v2 trap: %v.", err)
	}

	if val != 0 {
		t.Errorf("Received wrong value : %v", val)
	}

}
