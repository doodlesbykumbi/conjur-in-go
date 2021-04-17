package slosilo

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
)

type Key struct {
	privateKey *rsa.PrivateKey
}

func NewKey(pkeyDer []byte) (*Key, error) {
	pkey, err := x509.ParsePKCS1PrivateKey(pkeyDer)
	if err != nil {
		return nil, err
	}

	return &Key{privateKey: pkey}, nil
}

func sha256Digest(value []byte) []byte {
	hash := sha256.New()
	hash.Write(value)
	return hash.Sum(nil)
}

func (k Key) PrivateRSAPem() []byte  {
	return pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k.privateKey),
		},
	)
}

func (k Key) PublicPem() []byte  {
	bytes, err := x509.MarshalPKIXPublicKey(&k.privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type: "PUBLIC KEY",
			Bytes: bytes,
		},
	)
}

func (k Key) PublicRSAPem() []byte  {
	bytes := x509.MarshalPKCS1PublicKey(&k.privateKey.PublicKey)

	return pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PUBLIC KEY",
			Bytes: bytes,
		},
	)
}

func (k Key) Sign(value, salt []byte) ([]byte, error)  {
	value = concat(salt, value)

	signature, err := rsa.SignPKCS1v15(rand.Reader, k.privateKey, crypto.Hash(0), sha256Digest(value))
	if err != nil {
		return nil, err
	}

	return concat(signature, salt), nil
}

func (k Key) Verify(value, signature []byte) error  {
	salt := signature[len(signature) - 32:]
	signature = signature[:len(signature) - 32]

	value = concat(salt, value)
	return rsa.VerifyPKCS1v15(&k.privateKey.PublicKey, crypto.Hash(0), sha256Digest(value), signature)
}

func (k Key) Fingerprint() (string, error)  {
	der, err := x509.MarshalPKIXPublicKey(&k.privateKey.PublicKey)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sha256Digest(der)), nil
}
