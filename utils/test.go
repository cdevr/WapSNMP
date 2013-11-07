package main
import (
	snmp "github.com/cdevr/WapSNMP"
)

func main(){
	//snmp.DoWalkTest("127.0.0.1");
	snmp.DoWalkTestV3("127.0.0.1");
}
