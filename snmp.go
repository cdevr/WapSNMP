// Package wapsnmp provides an SNMP query library.
package wapsnmp

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"
	"io"
    "crypto/md5"
    "crypto/sha1"
	"crypto/aes"
	"crypto/cipher"
    "reflect"
	"strings"
	"bytes"
	"encoding/binary"
)

// The object type that lets you do SNMP requests.
type WapSNMP struct {
	Target    string        // Target device for these SNMP events.
	Community string        // Community to use to contact the device.
	Version   SNMPVersion   // SNMPVersion to encode in the packets.
	timeout   time.Duration // Timeout to use for all SNMP packets.
	retries   int           // Number of times to retry an operation.
	conn      net.Conn      // Cache the UDP connection in the object.
	//SNMP V3 variables
	user      string
	authPwd   string
	privPwd   string
	engineID  string
	//V3 temp variables
	authKey  string
	privKey  string
	engineBoots   int32
	engineTime    int32
	desIV		  uint32
	aesIV		  int64
}

const (
	bufSize int = 16384
	maxMsgSize int = 65000
)


func  password_to_key( password string, engineID string, hash_alg string) string{
	h := sha1.New()
	if hash_alg=="MD5" {
		h = md5.New()
	}

	count := 0;
	plen:=len(password);
	repeat := 1048576/plen;
	remain := 1048576%plen;
	for count < repeat {
		io.WriteString(h,password);
		count++;
	}
	if remain > 0 {
		io.WriteString(h,string(password[:remain]));
	}
	ku := string(h.Sum(nil))
	//fmt.Printf("ku=% x\n", ku)

	h.Reset();
	io.WriteString(h,ku);
	io.WriteString(h,engineID);
	io.WriteString(h,ku);
	localKey:=h.Sum(nil);
	//fmt.Printf("localKey=% x\n", localKey)

	return string(localKey);
}


// NewWapSNMP creates a new WapSNMP object. Opens a udp connection to the device that will be used for the SNMP packets.
func NewWapSNMP(target, community string, version SNMPVersion, timeout time.Duration, retries int) (*WapSNMP, error) {
	targetPort := fmt.Sprintf("%s:161", target)
	conn, err := net.DialTimeout("udp", targetPort, timeout)
	if err != nil {
		return nil, fmt.Errorf(`error connecting to ("udp", "%s") : %s`, targetPort, err)
	}
	return &WapSNMP{
		Target:target,
		Community: community,
		Version: version,
		timeout: timeout,
		retries: retries,
		conn: conn,
	}, nil
}

func NewWapSNMPv3(target, user, authPwd, privPwd string,  timeout time.Duration, retries int) (*WapSNMP, error) {
	targetPort := fmt.Sprintf("%s:161", target)
	conn, err := net.DialTimeout("udp", targetPort, timeout)
	if err != nil {
		return nil, fmt.Errorf(`error connecting to ("udp", "%s") : %s`, targetPort, err)
	}
	return &WapSNMP{
		Target:target,
		Version: SNMPv3,
		timeout: timeout,
		retries: retries,
		conn: conn,
		user: user,
		authPwd: authPwd,
		privPwd: privPwd,
	}, nil

}

/* NewWapSNMPOnConn creates a new WapSNMP object from an existing net.Conn.

It does not check if the provided target is valid.*/
func NewWapSNMPOnConn(target, community string, version SNMPVersion, timeout time.Duration, retries int, conn net.Conn) *WapSNMP {
	return &WapSNMP{
		Target:target,
		Community: community,
		Version: version,
		timeout: timeout,
		retries: retries,
		conn: conn,
	}
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

func (w *WapSNMP) Discover() (error) {
	msgID := getRandomRequestID()
	requestID := getRandomRequestID()
	v3Header, _:= EncodeSequence([]interface{}{Sequence,"",0,0,"","",""})
	flags:=string([]byte{4});
	USM := 0x03;
	req, err := EncodeSequence([]interface{}{
		Sequence, int(w.Version),
		[]interface{}{Sequence, msgID, maxMsgSize, flags, USM},
		string(v3Header),
		[]interface{}{Sequence, "", "",
			[]interface{}{AsnGetRequest, requestID, 0, 0, []interface{}{Sequence} }}})
	if err != nil {
		return err
	}

	response := make([]byte, bufSize)
	numRead, err := poll(w.conn, req, response, w.retries, 500*time.Millisecond)
	if err != nil {
		return err
	}
	fmt.Printf("numRead=%d\n",numRead);

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		fmt.Printf("Error decoding discover:%v\n",err);
		panic(err);
	}

	v3HeaderStr := decodedResponse[3].(string);
	if false {
		for i, val := range decodedResponse{
			fmt.Printf("%v:type=%v\n",i,reflect.TypeOf(val));
		}
	}

	v3HeaderDecoded, err := DecodeSequence([]byte(v3HeaderStr))
	if err != nil {
		fmt.Printf("Error 2 decoding:%v\n",err);
		return err
	}

	if false {
		for i, val := range v3HeaderDecoded{
			fmt.Printf("%v:type=%v\n",i,reflect.TypeOf(val))
		}
	}

	w.engineID=v3HeaderDecoded[1].(string);
	w.engineBoots=int32(v3HeaderDecoded[2].(int));
	w.engineTime=int32(v3HeaderDecoded[3].(int));
	w.aesIV=rand.Int63();
	//keys
	w.authKey = password_to_key(w.authPwd, w.engineID , "SHA1");
	privKey := password_to_key(w.privPwd, w.engineID , "SHA1");
	w.privKey = string(([]byte(privKey))[0:16])
	return  nil
}

func EncryptAESCFB(dst, src, key, iv []byte) error {
	aesBlockEncrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}
	aesEncrypter := cipher.NewCFBEncrypter(aesBlockEncrypter, iv)
	aesEncrypter.XORKeyStream(dst, src)
	return nil
}

func DecryptAESCFB(dst, src, key, iv []byte) error {
	aesBlockDecrypter, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil
	}
	aesDecrypter := cipher.NewCFBDecrypter(aesBlockDecrypter, iv)
	aesDecrypter.XORKeyStream(dst, src)
	return nil
}


func strXor(s1,s2 string) (string) {
	if len(s1) != len(s2){
		panic("strXor called with two strings of different length\n");
	}
	n := len(s1);
	b := make([]byte, n);
	for i:=0; i<n; i++ {
		b[i]=s1[i] ^ s2[i];
	}
	return string(b);
}

func (w WapSNMP) auth(wholeMsg string ) (string) {
	//Auth 
	padLen := 64-len(w.authKey);
	eAuthKey :=w.authKey+strings.Repeat("\x00",padLen);
	ipad := strings.Repeat("\x36",64);
	opad := strings.Repeat("\x5C",64);
	k1 := strXor(eAuthKey,ipad);
	k2 := strXor(eAuthKey,opad);
	h := sha1.New()
	io.WriteString(h,k1 + wholeMsg);
	tmp1 := string(h.Sum(nil));
	h.Reset();
	io.WriteString(h,k2 + tmp1);
	msgAuthParam := string(h.Sum(nil)[:12]);
	return msgAuthParam;
}

func (w WapSNMP) encrypt(payload string ) (string,string) {
	buf := new(bytes.Buffer);
	binary.Write(buf, binary.BigEndian, w.engineBoots)
	buf2 := new(bytes.Buffer);
	binary.Write(buf2, binary.BigEndian, w.engineTime)
	buf3 := new(bytes.Buffer);
	w.aesIV+=1;
	binary.Write(buf3, binary.BigEndian, w.aesIV)
	privParam := string(buf3.Bytes())
	iv := string(buf.Bytes()) + string(buf2.Bytes()) + privParam

	// Encrypt
	encrypted := make([]byte, len(payload))
	err := EncryptAESCFB(encrypted, []byte(payload), []byte(w.privKey), []byte(iv))
	if err != nil {
		panic(err)
	}
	return string(encrypted),privParam;
}

func (w WapSNMP) decrypt(payload,privParam string ) string {
	buf := new(bytes.Buffer);
	binary.Write(buf, binary.BigEndian, w.engineBoots)
	buf2 := new(bytes.Buffer);
	binary.Write(buf2, binary.BigEndian, w.engineTime)
	iv := string(buf.Bytes()) + string(buf2.Bytes()) + privParam

	// Decrypt
	decrypted := make([]byte, len(payload))
	err := DecryptAESCFB(decrypted, []byte(payload), []byte(w.privKey), []byte(iv))
	if err != nil {
		panic(err)
	}
	return string(decrypted);
}

// GetNext issues a GETNEXT SNMP request.
func (w *WapSNMP) GetNextV3(oid Oid) (*Oid, interface{}, error) {
	msgID := getRandomRequestID()
	requestID := getRandomRequestID()
	req, err := EncodeSequence(
		[]interface{}{Sequence,w.engineID,"",
			[]interface{}{AsnGetNextRequest, requestID, 0, 0,
				[]interface{}{Sequence,
					[]interface{}{Sequence, oid, nil}}}})
	if err != nil {
		panic(err);
	}

	encrypted,privParam := w.encrypt(string(req));

	v3Header, err:= EncodeSequence([]interface{}{Sequence,w.engineID,
				int(w.engineBoots),int(w.engineTime),w.user,strings.Repeat("\x00",12),privParam})
	if err != nil {
		panic(err);
	}

	flags:=string([]byte{7});
	USM := 0x03;
	packet, err := EncodeSequence([]interface{}{
		Sequence, int(w.Version),
		[]interface{}{Sequence, msgID, maxMsgSize, flags, USM},
		string(v3Header),
		encrypted})
	if err != nil {
		panic(err);
	}
	authParam := w.auth(string(packet));
	finalPacket := strings.Replace(string(packet),strings.Repeat("\x00",12),authParam,1);

	response := make([]byte, bufSize)
	numRead, err := poll(w.conn, []byte(finalPacket), response, w.retries, 500*time.Millisecond)
	if err != nil {
		return nil, nil, err
	}

	decodedResponse, err := DecodeSequence(response[:numRead])
	if err != nil {
		fmt.Printf("Error decoding getNext:%v\n",err);
		return nil, nil, err
	}
	/*
	for i, val := range decodedResponse{
		fmt.Printf("Resp:%v:type=%v\n",i,reflect.TypeOf(val));
	}
	*/

	v3HeaderStr := decodedResponse[3].(string);
	v3HeaderDecoded, err := DecodeSequence([]byte(v3HeaderStr))
	if err != nil {
		fmt.Printf("Error 2 decoding:%v\n",err);
		return nil, nil, err
	}

	w.engineID=v3HeaderDecoded[1].(string)
	w.engineBoots=int32(v3HeaderDecoded[2].(int))
	w.engineTime=int32(v3HeaderDecoded[3].(int))
	//respAuthParam := v3HeaderDecoded[5].(string)
	respPrivParam := v3HeaderDecoded[6].(string)

	encryptedResp := decodedResponse[4].(string);
	plainResp := w.decrypt(encryptedResp,respPrivParam);

	pduDecoded, err := DecodeSequence([]byte(plainResp))
	if err != nil {
		fmt.Printf("Error 3 decoding:%v\n",err);
		return nil, nil, err
	}

	// Find the varbinds
	respPacket := pduDecoded[3].([]interface{})
	varbinds := respPacket[4].([]interface{})
	result := varbinds[1].([]interface{})

	resultOid := result[1].(Oid)
	resultVal := result[2]

	return &resultOid, resultVal, nil
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

/* GetBulk is semantically the same as maxRepetitions getnext requests, but in a single GETBULK SNMP packet.

   Caveat: many devices will silently drop GETBULK requests for more than some number of maxrepetitions, if
   it doesn't work, try with a lower value and/or use GetTable. */
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
