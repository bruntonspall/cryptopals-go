package crypto

import (
	"bytes"
	"testing"
)

func TestUnhexbyte(t *testing.T) {
	expected := byte(14)
	actual := unhexbyte(byte('e'))
	if actual != expected {
		t.Error("Bytes not equal: ", actual, expected)
	}
	expected = byte(5)
	actual = unhexbyte(byte('5'))
	if actual != expected {
		t.Error("Bytes not equal: ", actual, expected)
	}
}

func TestHexToString(t *testing.T) {
	expected := "A"
	actual := string(HexDecodeString("41"))
	if actual != expected {
		t.Error("Strings not equal: ", actual, expected)
	}

	expected = "M"
	actual = string(HexDecodeString("4d"))
	if actual != expected {
		t.Error("Strings not equal: ", actual, expected)
	}

	expected = "/"
	actual = string(HexDecodeString("2F"))
	if actual != expected {
		t.Error("Strings not equal: ", actual, expected)
	}

	expected = "I'm killing your brain like a poisonous mushroom"
	actual = string(HexDecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
	if actual != expected {
		t.Error("Strings not equal: ", actual, expected)
	}
}
func TestStringToHex(t *testing.T) {
	var expected, actual string
	expected = "2f"
	actual = HexEncodeString([]byte("/"))
	if actual != expected {
		t.Error("Strings not equal: ", actual, expected)
	}
}

func TestB64Decode(t *testing.T) {
	var expected, actual string

	expected = "c29tZQ=="
	actual = B64EncodeString("some")
	if actual != expected {
		t.Error("Strings not equal: ", actual, expected)
	}

	expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	actual = B64EncodeString("I'm killing your brain like a poisonous mushroom")
	if actual != expected {
		t.Error("Strings not equal: ", actual, expected)
	}

}

func Test_xor_bytestream(t *testing.T) {
	stream1 := []byte{0x00, 0x7f, 0x10}
	stream2 := []byte{0x00, 0x00, 0x00}
	stream3 := []byte{0x01, 0x02, 0x03}

	var actual, _ = Xor(stream1, stream2)
	if !bytes.Equal(actual, stream1) {
		t.Error("Byte streams are not equal", actual, stream1)
	}

	actual, _ = Xor(stream1, stream3)
	expected := []byte{0x01, 0x7d, 0x13}
	if !bytes.Equal(actual, expected) {
		t.Error("Byte streams are not equal", actual, expected)
	}
}

func Test_Repeating_Xor(t *testing.T) {
	key := []byte{0x00, 0xff}
	cipher1 := []byte{0x01, 0x02}
	cipher2 := []byte{0x01, 0x02, 0x03, 0x04}

	var expected = []byte{0x01, 0xFD}
	var actual, _ = RepeatingXor(key, cipher1)
	if !bytes.Equal(actual, expected) {
		t.Error("Byte streams are not equal", actual, expected)
	}

	expected = []byte{0x01, 0xFD, 0x03, 0xFB}
	actual, _ = RepeatingXor(key, cipher2)
	if !bytes.Equal(actual, expected) {
		t.Error("Byte streams are not equal", actual, expected)
	}

}

func Test_Hammingdistance(t *testing.T) {
	var dist = HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if dist != 37 {
		t.Error("Hamming distance", dist, "is not 37")
	}
}

func Test_transposeBlocks(t *testing.T) {
	var data = []byte("This is a test stream!")
	var expected1 = []byte("Ti sats tem")
	var expected2 = []byte("hsi  etsra!")
	var actual = transposeBlocks(data, 2)
	if !bytes.Equal(actual[0], expected1) {
		t.Error("Byte streams are not equal", actual[0], expected1)
	}
	if !bytes.Equal(actual[1], expected2) {
		t.Error("Byte streams are not equal", actual[1], expected2)
	}
}

func Test_FindXorBlockSize(t *testing.T) {
	var data = []byte("This is a test message which is very long so that the system can reliably detect the keylenght using a fancy algorithm that looks for the hamming distance to see the distance between two byte streams, with the anticipation that the distance between bytes with the same key are probably small.")
	var cipher1, _ = RepeatingXor([]byte("xy"), data)
	var cipher2, _ = RepeatingXor([]byte("xyz"), data)
	var cipher3, _ = RepeatingXor([]byte("xyyz"), data)

	var actual = GuessBlockSize(cipher1)
	if actual != 2 {
		t.Error("Blocksize was", actual, "not 2")
	}
	actual = GuessBlockSize(cipher2)
	if actual != 3 {
		t.Error("Blocksize was", actual, "not 3")
	}
	actual = GuessBlockSize(cipher3)
	if actual != 4 {
		t.Error("Blocksize was", actual, "not 4")
	}
}
