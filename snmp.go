// Package wapsnmp provides an SNMP query library.
package wapsnmp

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"reflect"
	"time"
)

// WapSNMP is the type that lets you do SNMP requests.
type WapSNMP struct {
	Target    string        // Target device for these SNMP events.
	Community string        // Community to use to contact the device.
	Version   SNMPVersion   // SNMPVersion to encode in the packets.
	timeout   time.Duration // Timeout to use for all SNMP packets.
	retries   int           // Number of times to retry an operation.
	conn      net.Conn      // Cache the UDP connection in the object.
}

const (
	bufSize int = 16384
)

// NewWapSNMP creates a new WapSNMP object. Opens a udp connection to the device that will be used for the SNMP packets.
func NewWapSNMP(target, community string, version SNMPVersion, timeout time.Duration, retries int) (*WapSNMP, error) {
	targetPort := fmt.Sprintf("%s:161", target)
	conn, err := net.DialTimeout("udp", targetPort, timeout)
	if err != nil {
		return nil, fmt.Errorf(`error connecting to ("udp", "%s") : %s`, targetPort, err)
	}
	return &WapSNMP{target, community, version, timeout, retries, conn}, nil
}

// NewWapSNMPOnConn creates a new WapSNMP object from an existing net.Conn.
//
// It does not check if the provided target is valid.
func NewWapSNMPOnConn(target, community string, version SNMPVersion, timeout time.Duration, retries int, conn net.Conn) *WapSNMP {
	return &WapSNMP{target, community, version, timeout, retries, conn}
}

// Generate a valid SNMP request ID.
func getRandomRequestID() int {
	return int(rand.Int31())
}

// poll sends a packet and wait for a response. Both operations can timeout, they're retried up to retries times.
func poll(conn net.Conn, toSend []byte, respondBuffer []byte, retries int, timeout time.Duration) (int, error) {
	var err error
	for i := 0; i < retries+1; i++ {
		deadline := time.Now().Add(timeout)

		if err = conn.SetWriteDeadline(deadline); err != nil {
			log.Printf("Couldn't set write deadline. Retrying. Retry %d/%d\n", i, retries)
			continue
		}
		if _, err = conn.Write(toSend); err != nil {
			log.Printf("Couldn't write. Retrying. Retry %d/%d\n", i, retries)
			continue
		}

		deadline = time.Now().Add(timeout)
		if err = conn.SetReadDeadline(deadline); err != nil {
			log.Printf("Couldn't set read deadline. Retrying. Retry %d/%d\n", i, retries)
			continue
		}

		numRead := 0
		if numRead, err = conn.Read(respondBuffer); err != nil {
			log.Printf("Couldn't read. Retrying. Retry %d/%d\n", i, retries)
			continue
		}

		return numRead, nil
	}
	return 0, err
}

// Get sends an SNMP get request requesting the value for an oid.
func (w WapSNMP) Get(oid Oid) (interface{}, error) {
	requestID := getRandomRequestID()
	req, err := EncodeSequence([]interface{}{Sequence, int(w.Version), w.Community,
		[]interface{}{AsnGetRequest, requestID, 0, 0,
			[]interface{}{Sequence,
				[]interface{}{Sequence, oid, nil}}}})
	if err != nil {
		return nil, err
	}

	response := make([]byte, bufSize, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		return nil, err
	}

	// Fetch the varbinds out of the packet.
	respPacket := decodedResponse[3].([]interface{})
	varbinds := respPacket[4].([]interface{})
	result := varbinds[1].([]interface{})[2]

	return result, nil
}

// GetMultiple issues a single GET SNMP request requesting multiple values
func (w WapSNMP) GetMultiple(oids []Oid) (map[string]interface{}, error) {
	requestID := getRandomRequestID()

	varbinds := []interface{}{Sequence}
	for _, oid := range oids {
		varbinds = append(varbinds, []interface{}{Sequence, oid, nil})
	}
	req, err := EncodeSequence([]interface{}{Sequence, int(w.Version), w.Community,
		[]interface{}{AsnGetRequest, requestID, 0, 0, varbinds}})

	if err != nil {
		return nil, err
	}

	response := make([]byte, bufSize, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		return nil, err
	}

	// Find the varbinds
	respPacket := decodedResponse[3].([]interface{})
	respVarbinds := respPacket[4].([]interface{})

	result := make(map[string]interface{})
	for _, v := range respVarbinds[1:] { // First element is just a sequence
		oid := v.([]interface{})[1].(Oid).String()
		value := v.([]interface{})[2]
		result[oid] = value
	}

	return result, nil
}

// GetNext issues a GETNEXT SNMP request.
func (w WapSNMP) GetNext(oid Oid) (*Oid, interface{}, error) {
	requestID := getRandomRequestID()
	req, err := EncodeSequence([]interface{}{Sequence, int(w.Version), w.Community,
		[]interface{}{AsnGetNextRequest, requestID, 0, 0,
			[]interface{}{Sequence,
				[]interface{}{Sequence, oid, nil}}}})
	if err != nil {
		return nil, nil, err
	}

	response := make([]byte, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, 500*time.Millisecond)
	if err != nil {
		return nil, nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		return nil, nil, err
	}

	// Find the varbinds
	respPacket := decodedResponse[3].([]interface{})
	varbinds := respPacket[4].([]interface{})
	result := varbinds[1].([]interface{})

	resultOid := result[1].(Oid)
	resultVal := result[2]

	return &resultOid, resultVal, nil
}

// GetBulk is semantically the same as maxRepetitions getnext requests, but in a single GETBULK SNMP packet.
//
// Caveat: many devices will silently drop GETBULK requests for more than some number of maxrepetitions, if
// it doesn't work, try with a lower value and/or use GetTable.
func (w WapSNMP) GetBulk(oid Oid, maxRepetitions int) (map[string]interface{}, error) {
	requestID := getRandomRequestID()
	req, err := EncodeSequence([]interface{}{Sequence, int(w.Version), w.Community,
		[]interface{}{AsnGetBulkRequest, requestID, 0, maxRepetitions,
			[]interface{}{Sequence,
				[]interface{}{Sequence, oid, nil}}}})
	if err != nil {
		return nil, err
	}

	response := make([]byte, bufSize, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, 500*time.Millisecond)
	if err != nil {
		return nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		return nil, err
	}

	// Find the varbinds
	respPacket := decodedResponse[3].([]interface{})
	respVarbinds := respPacket[4].([]interface{})

	result := make(map[string]interface{})
	for _, v := range respVarbinds[1:] { // First element is just a sequence
		oid := v.([]interface{})[1].(Oid).String()
		value := v.([]interface{})[2]
		result[oid] = value
	}

	return result, nil
}

// GetTable efficiently gets an entire table from an SNMP agent. Uses GETBULK requests to go fast.
func (w WapSNMP) GetTable(oid Oid) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	lastOid := oid.Copy()
	for lastOid.Within(oid) {
		log.Printf("Sending GETBULK(%v, 50)\n", lastOid)
		results, err := w.GetBulk(lastOid, 50)
		if err != nil {
			return nil, fmt.Errorf("received GetBulk error => %v\n", err)
		}
		newLastOid := lastOid.Copy()
		for o, v := range results {
			oAsOid := MustParseOid(o)
			if oAsOid.Within(oid) {
				result[o] = v
			}
			newLastOid = oAsOid
		}

		if reflect.DeepEqual(lastOid, newLastOid) {
			// Not making any progress ? Assume we reached end of table.
			break
		}
		lastOid = newLastOid
	}
	return result, nil
}

// Close the net.conn in WapSNMP.
func (w WapSNMP) Close() error {
	return w.conn.Close()
}
