package wapsnmp

import (
	"encoding/hex"
	"reflect"
	"testing"
)

type LengthTest struct {
	Encoded      []byte
	Length       int
	LengthLength int // This is the length of the encoded length, as derived from the encoded value
}

func TestLengthDecodingEncoding(t *testing.T) {
	tests := []LengthTest{
		LengthTest{[]byte{0x26}, 38, 1},
		LengthTest{[]byte{0x82,0x00, 0xc9}, 201, 3},
		LengthTest{[]byte{0x82,0x00, 0xca}, 202, 3},
		LengthTest{[]byte{0x82,0x00, 0x9f}, 159, 3},
		LengthTest{[]byte{0x82,0x01, 0x70}, 368, 3},
		LengthTest{[]byte{0x82,0x00, 0xe3}, 227, 3},
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
	tests := map[int][]byte{
		3:          []byte{0x03},
		523:        []byte{0x02, 0x0b},
		1191105458: []byte{0x46, 0xfe, 0xd3, 0xb2},
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
		SequenceTest{"3003020100", []interface{}{Sequence, 0}},
		SequenceTest{"300804067075626c6963", []interface{}{Sequence, "public"}},
		SequenceTest{"300b04067075626c6963020100", []interface{}{Sequence, "public", 0}},
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
			t.Fatalf("Not decoded as expected. Encoded : %v\nExpected: %v\nResult  : %v", hex.EncodeToString(encodedBytes), test.Decoded, result)
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
