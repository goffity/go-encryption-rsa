package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func main() {
	payload := `{"name":"firstname"}`
	fmt.Printf("Original payload: %s", payload)

	encrypted, err := encrypt(payload, getPublicKey())
	if err != nil {
		_ = fmt.Errorf("ERROR: %s", err)
	}

	fmt.Printf("\n\nencrypted: %s", encrypted)

	fmt.Printf("\n\nDecrypt")

	decrypted, err := decrypt(encrypted, getPrivateKey())
	if err != nil {
		_ = fmt.Errorf("ERROR: %s", err)
	}

	fmt.Printf("\ndecrypted: %s", decrypted)
}

func getPublicKey() *rsa.PublicKey {
	keyFile, err := os.ReadFile("./key/public.pem")
	if err != nil {
		_ = fmt.Errorf("%s", err)
		os.Exit(1)
	}

	keyBlock, _ := pem.Decode(keyFile)
	if keyBlock == nil {
		_ = fmt.Errorf("ERROR: fail get public key, invalid key")
		os.Exit(1)
	}
	publicKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		_ = fmt.Errorf("ERROR: fail get idrsapub, %s", err.Error())
		return nil
	}
	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		return publicKey
	default:
		return nil
	}
}

func getPrivateKey() *rsa.PrivateKey {
	keyData, err := os.ReadFile("./key/private.pem")
	if err != nil {
		_ = fmt.Errorf("%s", err)
		os.Exit(1)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		_ = fmt.Errorf("ERROR: fail get public key, invalid key")
		os.Exit(1)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		_ = fmt.Errorf("ERROR: fail get idrsapub, %s", err.Error())
		os.Exit(1)
	}

	return privateKey
}

func encrypt(payload string, key *rsa.PublicKey) (string, error) {
	// params
	msg := []byte(payload)
	rnd := rand.Reader
	hash := sha256.New()

	// encrypt with OAEP
	cipherText, err := rsa.EncryptOAEP(hash, rnd, key, msg, nil)
	if err != nil {
		log.Printf("ERROR: fail to encrypt, %s", err.Error())
		return "", err
	}

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func decrypt(payload string, key *rsa.PrivateKey) (string, error) {
	// decode base64 encoded signature
	msg, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		log.Printf("ERROR: fail to base64 decode, %s", err.Error())
		return "", err
	}

	// params
	rnd := rand.Reader
	hash := sha256.New()

	// decrypt with OAEP
	plainText, err := rsa.DecryptOAEP(hash, rnd, key, msg, nil)
	if err != nil {
		log.Printf("ERROR: fail to decrypt, %s", err.Error())
		return "", err
	}

	return string(plainText), nil
}
