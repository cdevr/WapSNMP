
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

	packet:=make([]byte,3000);
	for {
		_,addr,err:=udpsock.ReadFromUDP(packet);
		if err!=nil{
			log.Fatal("udp read error\n");
		}

		log.Printf("trap from %s:\n",addr.IP);
		val, err := wsnmp.ParseTrap(packet)
		if err != nil {
			log.Fatal("Error testing parsing v2 trap: %v.", err)
		}

		if val != 0 {
			log.Printf("Received wrong value : %v", val)
		}
	}
	udpsock.Close();

}
