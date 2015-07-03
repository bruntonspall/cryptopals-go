package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var IncompatibleBuffers = errors.New("Buffers are incompatible")

const hextable = "0123456789abcdef"

func unhexbyte(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// Encodes a byte buffer into a hexadecimal representaton into the dst buffer
func HexEncode(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	for len(src) > 0 {
		dst[0] = hextable[src[0]>>4]
		dst[1] = hextable[src[0]&0x0f]
		dst = dst[2:]
		src = src[1:]
	}
}

// Decodes a byte buffer from a hexadecimal representation into the dst buffer
func HexDecode(dst, src []byte) {
	for len(src) > 0 {
		dst[0] = unhexbyte(src[0])<<4 + unhexbyte(src[1])
		dst = dst[1:]
		src = src[2:]
	}
}

// Decodes a string in hexadecimal representation into a byte buffer that it returns
func HexDecodeString(src string) []byte {
	var buffer = make([]byte, len(src)/2)
	HexDecode(buffer, []byte(src))
	return buffer
}

// Encodes a byte bugger into hexadecimal representation, returning the hex string
func HexEncodeString(src []byte) string {
	var buffer = make([]byte, len(src)*2)
	HexEncode(buffer, src)
	return string(buffer)
}

// Encodes a byte buffer into a base64 encoded string
func B64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

// Encodes a string into a base64 encoded string
func B64EncodeString(str string) string {
	return B64Encode([]byte(str))
}

// Decodes a base64 encoded string into a byte buffer
func B64Decode(str string) []byte {
	var dst = make([]byte, base64.StdEncoding.DecodedLen(len(str)))
	base64.StdEncoding.Decode(dst, []byte(str))
	return dst
}

// Decodes a base64 encoded string into a string
func B64DecodeString(str string) string {
	return string(B64Decode(str))
}

// Xors two streams of byte buffers together and returns a new buffer
// Both buffers must be the same size
func Xor(l, r []byte) ([]byte, error) {
	var buffer bytes.Buffer
	if len(l) != len(r) {
		return nil, IncompatibleBuffers
	}
	for i, b := range l {
		buffer.WriteByte(b ^ r[i])
	}
	return buffer.Bytes(), nil
}

// Xors a key buffer with a stream, where the key is repeated as necessary
func RepeatingXor(key, cipher []byte) ([]byte, error) {
	var buffer bytes.Buffer
	for i := 0; buffer.Len() < len(cipher); i++ {
		buffer.WriteByte(key[i%len(key)])
	}
	return Xor(buffer.Bytes(), cipher)
}

func calculateNonPrintable() []int {
	var nonPrintable = make([]int, 256)
	for i := 0; i < 255; i++ {
		switch {
		case i < 0x1f || i > 0x7f:
			nonPrintable[i] = -200
		case strings.ContainsAny("aeiouAEIOU", string(i)):
			nonPrintable[i] += 3
		case i >= int('a') && i <= int('z'):
			nonPrintable[i] += 1
		case i >= int('A') && i <= int('Z'):
			nonPrintable[i] += 1
		}
	}
	nonPrintable[9] = 0  // Tab
	nonPrintable[10] = 0 // Newline
	nonPrintable[13] = 0 // Carriage Return
	nonPrintable[32] = 4 // Space
	return nonPrintable
}

var nonPrintable = calculateNonPrintable()

// Checks whether a string is likely to be english
// Currently uses a combination of scoring unprintable characters low and counting spaces
func IsEnglish(s string) bool {
	score := 0
	for _, c := range s {
		score += nonPrintable[byte(c)]
	}
	return strings.Count(s, " ") > 4 && score > 0
	//if strings.ContainsAny(s, " aeiou") {
	//score = score + 1
	//}
	//if strings.ContainsAny(s, nonPrintable) {
	//score = score - 5
	//}

	return score > 40
}

// Count the number of bits set to 1 in a byte
// Count from right to left, zero-ing out bits as we count them
func countBits(b byte) int {
	var count = 0
	for b != 0 {
		count += 1
		b &= (b - 1)
	}
	return count
}

// Calculate the hamming distance between two equal length strings
func HammingDistance(l, r []byte) int {
	if len(l) != len(r) {
		return 0
	}
	var score = 0
	for i, _ := range l {
		score += countBits(l[i] ^ r[i])
	}
	return score
}

func transposeBlocks(src []byte, count int) [][]byte {
	var blocks = make([][]byte, count)
	for b := 0; b != count; b++ {
		blocks[b] = make([]byte, len(src)/count)
	}
	for i, b := range src {
		blocks[i%count][i/count] = b
	}
	return blocks
}

// Guess how long the key block is for an XOR ciphered bit of text
// Do so by testing blocks based on key size and seeing what the hamming distance is
func GuessBlockSize(cipher []byte) int {
	var best, bestSize = 999, 0
	for blocksize := 1; blocksize < 8; blocksize++ {
		fmt.Println("Testing blocksize", blocksize)
		var t = 0
		for block := 0; block < 8; block++ {
			var start = block * blocksize
			var middle = start + blocksize
			var end = middle + blocksize
			if end > len(cipher) {
				continue
			}
			var subtotal = HammingDistance(cipher[start:middle], cipher[middle:end]) / blocksize
			t += subtotal
		}
		//t /= 8
		fmt.Println("Is", t, "<", best)
		if t < best {
			best = t
			bestSize = blocksize
		}
	}
	return bestSize
}
