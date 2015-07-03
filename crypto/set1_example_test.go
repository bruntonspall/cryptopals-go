package crypto

import (
	"fmt"
	"io/ioutil"
	"strings"
)

func Example_set1_challenge1() {
	fmt.Println(B64Encode(HexDecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))
	// Output:
	// SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
}

func Example_set1_challenge2() {
	var s1 = HexDecodeString("1c0111001f010100061a024b53535009181c")
	var s2 = HexDecodeString("686974207468652062756c6c277320657965")
	var actual, _ = Xor(s1, s2)
	fmt.Println(string(actual))
	fmt.Println(HexEncodeString(actual))
	// Output:
	// the kid don't play
	// 746865206b696420646f6e277420706c6179
}

func Example_set1_challenge3() {
	var ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	var i byte
	for i = 0; i < 255; i++ {
		var guess, _ = RepeatingXor([]byte{i}, []byte(HexDecodeString(ciphertext)))
		if IsEnglish(string(guess)) {
			fmt.Println(string(guess))
		}
	}
	// Output:
	// Cooking MC's like a pound of bacon
}

func Example_set1_challenge4() {
	var i byte
	var f, err = ioutil.ReadFile("4.txt")
	if err != nil {
		panic(err)
	}
	var ciphers = strings.Split(string(f), "\n")
	for _, ciphertext := range ciphers {
		for i = 0; i < 255; i++ {
			var guess, _ = RepeatingXor([]byte{i}, []byte(HexDecodeString(ciphertext)))
			if IsEnglish(string(guess)) {
				fmt.Println(string(guess))
			}
		}

	}
	// Output:
	// Now that the party is jumping
}

func Example_set1_challenge5() {
	var plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	var key = "ICE"
	var cipher, err = RepeatingXor([]byte(key), []byte(plaintext))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(HexEncodeString(cipher))
	// Output:
	// 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
}
