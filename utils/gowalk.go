package main
import (
	//snmp "github.com/cdevr/WapSNMP"
	snmp "github.com/tiebingzhang/WapSNMP"
)

func main(){
	//snmp.DoWalkTest("127.0.0.1");
	snmp.DoWalkTestV3("10.0.217.204","1.3.6.1.4.1.27822.8.1.1", "pcb.snmpv3","SHA1","this_is_my_pcb","AES", "my_pcb_is_4_me");
}
