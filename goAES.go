package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

var pass = flag.String("pass", "Password111111111111111111111111", "32 char password phrase- can be set to anything but keep it private")
var text = flag.String("text", "HelloWorld", "plain text to encode")
var cipherText = flag.String("cipher", "", "cipher text")
var verbose = flag.Bool("verbose", false, "verbose flag")

func main() {
	flag.Parse()
	key := []byte(*pass) // 32 bytes
	if len(os.Args) < 2 {
		println("usage: goAES -pass Password111111111111111111111111 -text HelloWorld")
		println("or")
		println("usage: goAES -pass Password111111111111111111111111 -cipher HnOnMPZAb32fz1f80VIL2pjQ+ahp/upo")
		os.Exit(1)
	}
	if *cipherText == "" {
		plaintext := []byte(*text)
		ciphertextOutput, err := encrypt(key, plaintext)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(ciphertextOutput))
	} else {
		cipherBytes, err := base64.StdEncoding.DecodeString(*cipherText)
		if err != nil {
			log.Fatal(err)
		}

		result, err := decrypt(key, cipherBytes)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", result)
	}
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	if *verbose {
		println("blocksize=", aes.BlockSize, "ciphertext=", string(ciphertext))
	}
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	if *verbose {
		println("iv", base64.StdEncoding.EncodeToString(iv), "cipher text", base64.StdEncoding.EncodeToString(iv))
	}
	cfb := cipher.NewCFBDecrypter(block, []byte(iv))
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}
