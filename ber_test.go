package wapsnmp

import (
	"encoding/base64"
	"encoding/hex"
	"net"
	"reflect"
	"testing"
)

type Counter32Test struct {
	Encoded  []byte
	Expected int64
}

func TestCounter32Decoding(t *testing.T) {
	tests := []Counter32Test{
		{[]byte{0x04, 0x50, 0xd8}, 282840},
		{[]byte{0x04, 0xc8}, 1224},
		{[]byte{0x56, 0x60, 0x60, 0xeb}, 1449156843},
	}

	for _, test := range tests {
		value, err := DecodeInteger(test.Encoded)
		if err != nil {
			t.Errorf("Decoding %v led to error %v", test.Encoded, err)
		}
		if value != test.Expected {
			t.Errorf("Counter32 not decoded as expected %v => %v, expected %v", test.Encoded, value, test.Expected)
		}
	}
}

type LengthTest struct {
	Encoded      []byte
	Length       uint64
	LengthLength int // This is the length of the encoded length, as derived from the encoded value
}

func TestLengthDecodingEncoding(t *testing.T) {
	tests := []LengthTest{
		{[]byte{0x26}, 38, 1},
		{[]byte{0x81, 0xc9}, 201, 2},
		{[]byte{0x81, 0xca}, 202, 2},
		{[]byte{0x81, 0x9f}, 159, 2},
		{[]byte{0x82, 0x01, 0x70}, 368, 3},
		{[]byte{0x81, 0xe3}, 227, 2},
	}

	for _, test := range tests {
		length, lenLength, err := DecodeLength(test.Encoded)
		if length != test.Length || lenLength != test.LengthLength || err != nil {
			t.Errorf("Failed to decode %v, expected (%v, %v), result (%v, %v) err: %v", hex.EncodeToString(test.Encoded), test.Length, test.LengthLength, length, lenLength, err)
			continue
		}
		// Re-encode
		bytes := EncodeLength(test.Length)
		if !reflect.DeepEqual(bytes, test.Encoded) {
			t.Errorf("Length not encoded as expected. Length  : %v\nExpected: %v\nResult  : %v", test.Length, hex.EncodeToString(test.Encoded), hex.EncodeToString(bytes))
		}
	}
}

func TestDecodeEncodeInteger(t *testing.T) {
	tests := map[int64][]byte{
		3:          {0x03},
		523:        {0x02, 0x0b},
		1191105458: {0x46, 0xfe, 0xd3, 0xb2},
		-91:        {0xff, 0xa5},
		-654854:    {0xff, 0xf6, 0x01, 0xfa},
	}

	for testValue, testEncode := range tests {
		encode := EncodeInteger(testValue)
		if !reflect.DeepEqual(testEncode, encode) {
			t.Errorf("Failed to encode %v. EncodeInteger => %v Expected %v", testValue, hex.EncodeToString(encode), hex.EncodeToString(testEncode))
			continue
		}

		value, err := DecodeInteger(testEncode)
		if err != nil {
			t.Errorf("Decoding %v failed. Err = %v", hex.EncodeToString(testEncode), err)
			continue
		}
		if value != testValue {
			t.Errorf("Decoding %v gave wrong result. Result => %v Expected => %v", hex.EncodeToString(testEncode), value, testValue)
			continue
		}
	}
}

type SequenceTest struct {
	Encoded string
	Decoded []interface{}
}

func TestSequenceDecoding(t *testing.T) {
	SequenceTests := []SequenceTest{
		{"3003020100", []interface{}{Sequence, int64(0)}},
		{"300804067075626c6963", []interface{}{Sequence, "public"}},
		{"300b04067075626c6963020100", []interface{}{Sequence, "public", int64(0)}},
		{"3013060b2b060102010202010a84234104566060eb", []interface{}{Sequence, MustParseOid("1.3.6.1.2.1.2.2.1.10.547"), Counter(1449156843)}},
		{"300f060a2b060102010202010508420100", []interface{}{Sequence, MustParseOid("1.3.6.1.2.1.2.2.1.5.8"), Gauge(0)}},
		{"3012060a2b0601020102020105344204ffffffff", []interface{}{Sequence, MustParseOid("1.3.6.1.2.1.2.2.1.5.52"), Gauge(4294967295)}},
		{"300f060a2b060102010202011601060100", []interface{}{Sequence, MustParseOid("1.3.6.1.2.1.2.2.1.22.1"), MustParseOid("0.0")}},
		{"3006400401020304", []interface{}{Sequence, net.ParseIP("1.2.3.4")}},
	}

	for _, test := range SequenceTests {
		encodedBytes, err := hex.DecodeString(test.Encoded)
		if err != nil {
			t.Fatalf("Error when decoding hex %s", encodedBytes)
		}
		result, err := DecodeSequence(encodedBytes)
		if err != nil {
			t.Fatalf("Error while decoding %v => %v", hex.EncodeToString(encodedBytes), err)
		}
		if !reflect.DeepEqual(result, test.Decoded) {
			t.Errorf("Not decoded as expected. Encoded : %v\nExpected: %v\nResult  : %v", hex.EncodeToString(encodedBytes), test.Decoded, result)
		}
	}

	for _, test := range SequenceTests {
		encodedBytes, err := hex.DecodeString(test.Encoded)
		if err != nil {
			t.Fatalf("Error when decoding hex %s", encodedBytes)
		}
		result, err := EncodeSequence(test.Decoded)
		if err != nil {
			t.Fatalf("Error while encoding %v => %v", test.Decoded, err)
		}
		if !reflect.DeepEqual(result, encodedBytes) {
			here := ""
			for idx := 0; idx < len(result) && idx < len(encodedBytes); idx++ {
				if (result)[idx] != encodedBytes[idx] {
					break
				}
				here += "  "
			}
			here += "^ first difference"

			t.Errorf("Not encoded as expected. Decoded : %v\nExpected: %v\nResult  : %v\n          %v", test.Decoded, hex.EncodeToString(encodedBytes), hex.EncodeToString(result), here)
		}
	}
}

func TestDecodeNoSuchInstance(t *testing.T) {
	_, err := DecodeSequence([]byte{0x30, 0x0b, 0x06, 0x07, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x81, 0x00})
	if err == nil {
		t.Error("Error not reported as expected")
	}
}

func TestTrapV2(t *testing.T) {
	// Generated via:
	// $ snmptrap -v 2c -c public localhost:1600 '' SNMPv2-MIB::snmpTrapOID SNMPv2-MIB::sysName.0 s "test"
	s := "MFgCAQEEBnB1YmxpY6dLAgRAPUXKAgEAAgEAMD0wEAYIKwYBAgEBAwBDBAbPOZIwFwYKKwYBBgMBAQQBAAYJKwYBBgMBAQQBMBAGCCsGAQIBAQUABAR0ZXN0"
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("DecodeString(_) = _, %v, want nil", err)
	}
	d, err := DecodeSequence(data)
	if err != nil {
		t.Fatalf("DecodeSequence(_) = _, %v, want nil", err)
	}

	v := d[3].([]interface{})[4].([]interface{})[3].([]interface{})[2].(string)
	if v != "test" {
		t.Fatalf("Failed to decode trap sequence, got %q want 'test'", v)
	}
}
