package slosilo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const ivSize = 12
const tagSize = aes.BlockSize
const versionMagic = byte('G')

type SymmetricCipher interface {
	Decrypt(aad, packedText []byte) ([]byte, error)
	Encrypt(aad, plainText []byte) ([]byte, error)
}
type Symmetric struct {
	aesgcm cipher.AEAD
}

func NewSymmetric(key []byte) (SymmetricCipher, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	return &Symmetric{aesgcm: aesgcm}, nil
}

func (s Symmetric) Decrypt(aad, packedText []byte) ([]byte, error) {
	if len(packedText) < aes.BlockSize {
		return nil, errors.New("ciphertext block size is too short")
	}

	cipherText, iv := UnpackCipherData(packedText)

	return s.aesgcm.Open(nil, iv, cipherText, aad)
}

func RandomNonce() ([]byte, error) {
	// Never use more than 2^32 random nonces with a given key because of
	// the risk of a repeat.
	return RandomBytes(ivSize)
}

func RandomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return nil, err
	}

	return value, nil
}

func (s Symmetric) encrypt(aad, plainText, nonce []byte) ([]byte, error) {
	if len(nonce) < ivSize {
		return nil, errors.New("nonce size is too short")
	}

	cipherTextWithTag := s.aesgcm.Seal(nil, nonce, plainText, aad)
	packedText := PackCipherData(cipherTextWithTag, nonce)

	return packedText, nil
}

func (s Symmetric) Encrypt(aad, plainText []byte) ([]byte, error) {
	nonce, err := RandomNonce()
	if err != nil {
		return nil, err
	}

	return s.encrypt(aad, plainText, nonce)
}

func PackCipherData(cipherTextWithTag []byte, iv []byte) []byte {
	iv = iv[:ivSize]

	tagStartIndex := len(cipherTextWithTag) - tagSize
	tag := cipherTextWithTag[tagStartIndex:]
	cipherText := cipherTextWithTag[:tagStartIndex]

	dataLength := 1 + tagSize + ivSize + len(cipherText)
	data := make([]byte, dataLength)

	// TODO: this is weird, it tends to be tagSize here not tag!
	// "#{VERSION_MAGIC}#{tag}#{iv}#{ctext}"
	data[0] = versionMagic
	index := 1

	copy(data[index:], tag)
	index += tagSize

	copy(data[index:], iv)
	index += ivSize

	copy(data[index:], cipherText)

	return data
}

func UnpackCipherData(packedText []byte) ([]byte, []byte) {
	// "#{VERSION_MAGIC}#{tag}#{iv}#{ctext}"

	// version := packedText[1:]
	// TODO: maybe assert on version
	index := 1

	nextIndex := index + tagSize
	tag := packedText[index:nextIndex]
	index = nextIndex

	nextIndex = index + ivSize
	iv := packedText[index:nextIndex]
	index = nextIndex

	cipherText := append(packedText[index:], tag...)

	return cipherText, iv
}
