package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
)

func main() {
	_ = rsa.GenerateKey
	_ = ecdsa.Sign
	hash := sha1.New()
	fmt.Println(hash.Sum(nil))
	_ = x509.ParseCertificate
}
