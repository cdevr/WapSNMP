
package main

import (
	snmp "github.com/tiebingzhang/WapSNMP"
	"log"
	"net"
	"math/rand"
	"time"
)

func myUDPServer(listenIPAddr string, port int) *net.UDPConn {
    addr := net.UDPAddr{
        Port: port,
        IP: net.ParseIP(listenIPAddr),
    }
    conn, err := net.ListenUDP("udp", &addr)
    if err != nil {
		log.Printf("udp Listen error.");
        panic(err)
    }
	return conn;
}

func main() {
	rand.Seed(0)
	target := ""
	community := ""
	version := snmp.SNMPv2c

	udpsock := myUDPServer("0.0.0.0",162);

	wsnmp := snmp.NewWapSNMPOnConn(target, community, version, 2*time.Second, 5, udpsock)
	defer wsnmp.Close()

	wsnmp.Trapusers = append(wsnmp.Trapusers,snmp.V3user{ "hcm.snmpv3","SHA1","this_is_my_hcm","AES","my_hcm_is_4_me" });

	packet:=make([]byte,3000);
	for {
		_,addr,err:=udpsock.ReadFromUDP(packet);
		if err!=nil{
			log.Fatal("udp read error\n");
		}

		log.Printf("Received trap from %s:\n",addr.IP);

		err = wsnmp.ParseTrap(packet)
		if err != nil {
			log.Printf("Error processing trap: %v.", err)
		}
	}
	udpsock.Close();

}
