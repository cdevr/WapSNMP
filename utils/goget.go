package main
import (
	snmp "github.com/tiebingzhang/WapSNMP"
)

func main(){
	snmp.DoGetTestV3("10.0.217.204","1.3.6.1.4.1.27822.8.1.1.6.0", "pcb.snmpv3","SHA1","this_is_my_pcb","AES", "my_pcb_is_4_me");
}
