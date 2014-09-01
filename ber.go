package wapsnmp

/* This file implements BER ASN1 encoding and decoding.

References : http://rane.com/note161.html

This package was made due to the inability of the encoding/asn1 library to
parse SNMP packets received from actual network devices. In order to fix
encoding/asn1 I would need to make deep changes in that core library file.

First difference is that this file works differently from the standard
libary one : this will convert between []interface{} and ASN1, whereas
encoding/asn1 converts between structs and ASN1.

Furthermore encoding/asn1 is an implementation of DER, whereas this does BER
(DER is a subset of BER). They're different like xml and html are different.
In theory html should be valid xml, in practice it's not. This means you can't
use an existing xml parser to parse html if you communicate with external
devices, because it wouldn't parse. Likewise you can't use a DER parser to
parse BER.
*/

import (
	"fmt"
	"time"
)

// BERType is a type for Type of the TLV field.
type BERType uint8

// Counter is a type to distinguish Counter32 from just an int.
type Counter int

// Counter64 is a type to distinguish Counter64 from just an int.
type Counter64 int

// Gauge is a type to distinguish Gauge32 from just an int.
type Gauge int

// Gauge64 is a type to distinguish Gauge64 from just an int.
type Gauge64 int

// Constants for the different types of the TLV fields.
const (
	AsnBoolean     BERType = 0x01
	AsnInteger     BERType = 0x02
	AsnBitStr      BERType = 0x03
	AsnOctetStr    BERType = 0x04
	AsnNull        BERType = 0x05
	AsnObjectID    BERType = 0x06
	AsnSequence    BERType = 0x10
	AsnSet         BERType = 0x11
	AsnUniversal   BERType = 0x00
	AsnApplication BERType = 0x40
	AsnContext     BERType = 0x80
	AsnPrivate     BERType = 0xC0
	AsnPrimitive   BERType = 0x00
	AsnConstructor BERType = 0x20

	AsnLongLen     BERType = 0x80
	AsnExtensionID BERType = 0x1F
	AsnBit8        BERType = 0x80

	Integer     BERType = AsnUniversal | 0x02
	Integer32   BERType = AsnUniversal | 0x02
	Bitstring   BERType = AsnUniversal | 0x03
	Octetstring BERType = AsnUniversal | 0x04
	Null        BERType = AsnUniversal | 0x05
	UOid        BERType = AsnUniversal | 0x06
	Sequence    BERType = AsnConstructor | 0x10

	AsnIpaddress BERType = AsnApplication | 0x00
	AsnCounter   BERType = AsnApplication | 0x01
	AsnCounter32 BERType = AsnApplication | 0x01
	AsnGauge     BERType = AsnApplication | 0x02
	AsnGauge32   BERType = AsnApplication | 0x02
	AsnTimeticks BERType = AsnApplication | 0x03
	Opaque       BERType = AsnApplication | 0x04
	AsnCounter64 BERType = AsnApplication | 0x06

	AsnGetRequest     BERType = 0xa0
	AsnGetNextRequest BERType = 0xa1
	AsnGetResponse    BERType = 0xa2
	AsnSetRequest     BERType = 0xa3
	AsnGetBulkRequest BERType = 0xa5

	NoSuchInstance BERType = 0x81
	EndOfMibView   BERType = 0x82
)

// SNMPVersion is a type to indicate which SNMP version is in use.
type SNMPVersion uint8

// List of the supported snmp versions.
const (
	SNMPv1  SNMPVersion = 0
	SNMPv2c SNMPVersion = 1
)

// EncodeLength encodes an integer value as a BER compliant length value.
func EncodeLength(length int) []byte {
	// The first bit is used to indicate whether this is the final byte
	// encoding the length. So, if the first bit is 0, just return a one
	// byte response containing the byte-encoded length.
	if length <= 0x7f {
		return []byte{byte(length)}
	}

	// If the length is bigger the format is, first bit 1 + the rest of the
	// bits in the first byte encode the length of the length, then follows
	// the actual length.

	// Technically the SNMP spec allows for packet lengths longer than can be
	// specified in a 127-byte encoded integer, however, going out on a limb
	// here, I don't think I'm going to support a use case that insane.

	r := EncodeInteger(length)
	numOctets := len(r)
	result := make([]byte, 1+numOctets)
	result[0] = 0x80 | byte(numOctets)
	for i, b := range r {
		result[1+i] = b
	}
	return result
}

// DecodeLength returns the length and the length of the length or an error.
//
// Caveats: Does not support indefinite length. Couldn't find any
// SNMP packet dump actually using that.
func DecodeLength(toparse []byte) (int, int, error) {
	// If the first bit is zero, the rest of the first byte indicates the length. Values up to 127 are encoded this way (unless you're using indefinite length, but we don't support that)

	if toparse[0] == 0x80 {
		return 0, 0, fmt.Errorf("we don't support indefinite length encoding")
	}
	if toparse[0]&0x80 == 0 {
		return int(toparse[0]), 1, nil
	}

	// If the first bit is one, the rest of the first byte encodes the length of then encoded length. So read how many bytes are part of the length.
	numOctets := int(toparse[0] & 0x7f)
	if len(toparse) < 1+numOctets {
		return 0, 0, fmt.Errorf("invalid length")
	}

	// Decode the specified number of bytes as a BER Integer encoded
	// value.
	val, err := DecodeInteger(toparse[1 : numOctets+1])
	if err != nil {
		return 0, 0, err
	}

	return val, 1 + numOctets, nil
}

// DecodeInteger decodes an integer.
//
// Will error out if it's longer than 64 bits.
func DecodeInteger(toparse []byte) (int, error) {
	if len(toparse) > 8 {
		return 0, fmt.Errorf("don't support more than 64 bits")
	}
	val := 0
	for _, b := range toparse {
		val = val*256 + int(b)
	}
	return val, nil
}

// EncodeInteger encodes an integer to BER format.
func EncodeInteger(toEncode int) []byte {
	// Calculate the length we'll need for the encoded value.
	l := 1
	i := toEncode
	for i > 255 {
		i = i >> 8
		l++
	}

	// Now create a byte array of the correct length and copy the value into it.
	result := make([]byte, l)
	for i = 0; i < l; i++ {
		result[i] = byte(toEncode >> uint(8*(l-i-1)))
	}
	return result
}

// DecodeSequence decodes BER binary data into into *[]interface{}.
func DecodeSequence(toparse []byte) ([]interface{}, error) {
	var result []interface{}

	if len(toparse) < 2 {
		return nil, fmt.Errorf("sequence cannot be shorter than 2 bytes")
	}
	sqType := BERType(toparse[0])
	result = append(result, sqType)
	// Bit 6 is the P/C primitive/constructed bit. Which means it's a set, essentially.
	if sqType != Sequence && (toparse[0]&0x20 == 0) {
		return nil, fmt.Errorf("byte array parsed in is not a sequence")
	}
	seqLength, seqLenLen, err := DecodeLength(toparse[1:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse sequence length (seq len len: %d)", seqLenLen)
	}

	if seqLength == 0 {
		return result, nil
	}

	lidx := 0
	idx := 1 + seqLenLen
	// Let's guarantee progress.
	for idx < len(toparse) && idx > lidx {
		berType := toparse[idx]
		berLength, berLenLen, err := DecodeLength(toparse[idx+1:])
		if err != nil {
			return nil, fmt.Errorf("length parse error @ idx %v", idx)
		}
		berValue := toparse[idx+1+berLenLen : idx+1+berLenLen+berLength]
		berAll := toparse[idx : idx+1+berLenLen+berLength]

		switch BERType(berType) {
		case AsnBoolean:
			if berLength != 1 {
				return nil, fmt.Errorf("boolean length != 1 @ idx %v", idx)
			}
			result = append(result, berValue[0] == 0)
		case AsnInteger:
			decodedValue, err := DecodeInteger(berValue)
			if err != nil {
				return nil, err
			}
			result = append(result, decodedValue)
		case AsnOctetStr:
			result = append(result, string(berValue))
		case AsnNull:
			result = append(result, nil)
		case AsnObjectID:
			oid, err := DecodeOid(berValue)
			if err != nil {
				return nil, fmt.Errorf("Error decoding oid %v : %v", berValue, err)
			}
			result = append(result, *oid)
		case AsnCounter32:
			val, err := DecodeInteger(berValue)
			if err != nil {
				return nil, fmt.Errorf("Error decoding integer %v : %v", berValue, err)
			}
			result = append(result, Counter(val))
		case AsnGauge32:
			val, err := DecodeInteger(berValue)
			if err != nil {
				return nil, fmt.Errorf("Error decoding integer %v : %v", berValue, err)
			}
			result = append(result, Gauge(val))
		case AsnTimeticks:
			val, err := DecodeInteger(berValue)
			if err != nil {
				return nil, fmt.Errorf("Error decoding integer %v : %v", berValue, err)
			}
			result = append(result, time.Duration(val)*10*time.Millisecond)
		case Sequence:
			pdu, err := DecodeSequence(berAll)
			if err != nil {
				return nil, err
			}
			result = append(result, pdu)
		case AsnGetNextRequest, AsnGetRequest, AsnGetResponse:
			pdu, err := DecodeSequence(berAll)
			if err != nil {
				return nil, err
			}
			result = append(result, pdu)
		case NoSuchInstance:
			return nil, fmt.Errorf("No such instance. Received bytes: %v", toparse)
		case EndOfMibView:
			return nil, fmt.Errorf("End of mib view. Received bytes: %v", toparse)
		default:
			return nil, fmt.Errorf("did not understand type %v", berType)
		}

		lidx = idx
		idx = idx + 1 + berLenLen + berLength
	}

	return result, nil
}

// EncodeSequence will encode an []interface{} into an SNMP bytestream.
func EncodeSequence(toEncode []interface{}) ([]byte, error) {
	switch toEncode[0].(type) {
	default:
		return nil, fmt.Errorf("first element of sequence to encode should be sequence type")
	case BERType:
		// OK
	}

	seqType := toEncode[0].(BERType)
	var toEncap []byte
	for _, val := range toEncode[1:] {
		switch val := val.(type) {
		default:
			return nil, fmt.Errorf("couldn't handle type %T", val)
		case nil:
			toEncap = append(toEncap, byte(AsnNull))
			toEncap = append(toEncap, 0)
		case int:
			enc := EncodeInteger(val)
			// TODO encode length ?
			toEncap = append(toEncap, byte(AsnInteger))
			toEncap = append(toEncap, byte(len(enc)))
			for _, b := range enc {
				toEncap = append(toEncap, b)
			}
		case Counter:
			enc := EncodeInteger(int(val))
			// TODO encode length ?
			toEncap = append(toEncap, byte(AsnCounter32))
			toEncap = append(toEncap, byte(len(enc)))
			for _, b := range enc {
				toEncap = append(toEncap, b)
			}
		case Gauge:
			enc := EncodeInteger(int(val))
			// TODO encode length ?
			toEncap = append(toEncap, byte(AsnGauge32))
			toEncap = append(toEncap, byte(len(enc)))
			for _, b := range enc {
				toEncap = append(toEncap, b)
			}
		case string:
			enc := []byte(val)
			toEncap = append(toEncap, byte(AsnOctetStr))
			for _, b := range EncodeLength(len(enc)) {
				toEncap = append(toEncap, b)
			}
			for _, b := range enc {
				toEncap = append(toEncap, b)
			}
		case Oid:
			enc, err := val.Encode()
			if err != nil {
				return nil, err
			}
			toEncap = append(toEncap, byte(AsnObjectID))
			encLen := EncodeLength(len(enc))
			for _, b := range encLen {
				toEncap = append(toEncap, b)
			}
			for _, b := range enc {
				toEncap = append(toEncap, b)
			}
		case []interface{}:
			enc, err := EncodeSequence(val)
			if err != nil {
				return nil, err
			}
			for _, b := range enc {
				toEncap = append(toEncap, b)
			}
		}
	}

	l := EncodeLength(len(toEncap))
	// Encode length ...
	result := []byte{byte(seqType)}
	for _, b := range l {
		result = append(result, b)
	}
	for _, b := range toEncap {
		result = append(result, b)
	}
	return result, nil
}
