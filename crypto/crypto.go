package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func encrypt(key []byte, message string) (ciphertext []byte, iv []byte) {
	plaintext := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	iv = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext = aesgcm.Seal(nil, iv, plaintext, nil)
	//fmt.Printf("%x\n", ciphertext)

	return
}

func decrypt(key []byte, ciphertext []byte, iv []byte) (message string) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	message = string(plaintext)

	return
}

func main() {
	key, _ := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Digite a mensagem: ")
	fmt.Print("->")
	msg, _ := reader.ReadString('\n')

	encryptedMsg, iv := encrypt(key, msg)
	decryptedMsg := decrypt(key, encryptedMsg, iv)

	fmt.Printf("CIPHER KEY: %x\n", key)
	fmt.Printf("ENCRYPTED: %x\n", encryptedMsg)
	fmt.Printf("DECRYPTED: %s\n", decryptedMsg)
}
