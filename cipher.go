package pkcs7

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	smcipher "github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/padding"
	"github.com/emmansun/gmsm/sm4"
)

var (
	// Encryption Algorithms
	OIDEncryptionAlgorithmDESCBC = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}

	OIDEncryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}

	OIDEncryptionAlgorithmAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OIDEncryptionAlgorithmAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	OIDEncryptionAlgorithmAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	OIDEncryptionAlgorithmAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	OIDEncryptionAlgorithmAES192GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
	OIDEncryptionAlgorithmAES256GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}

	OIDEncryptionAlgorithmSM4GCM = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 8}
	OIDEncryptionAlgorithmSM4CBC = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 2}
	OIDEncryptionAlgorithmSM4ECB = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104, 1}
	OIDEncryptionAlgorithmSM4    = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 104}
)

// Cipher represents a cipher for encrypting the key material.
type Cipher interface {
	// KeySize returns the key size of the cipher, in bytes.
	KeySize() int
	// Encrypt encrypts the key material.
	Encrypt(key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error)
	// Decrypt decrypts the key material.
	Decrypt(key []byte, parameters *asn1.RawValue, ciphertext []byte) ([]byte, error)
	// OID returns the OID of the cipher specified.
	OID() asn1.ObjectIdentifier
}

var ciphers = map[string]Cipher{
	OIDEncryptionAlgorithmSM4.String(): &ecbBlockCipher{baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      OIDEncryptionAlgorithmSM4}},
	OIDEncryptionAlgorithmSM4ECB.String(): &ecbBlockCipher{baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      OIDEncryptionAlgorithmSM4ECB}},
	OIDEncryptionAlgorithmDESCBC.String(): &cbcBlockCipher{baseBlockCipher: baseBlockCipher{
		keySize:  8,
		newBlock: des.NewCipher,
		oid:      OIDEncryptionAlgorithmDESCBC}, ivSize: des.BlockSize},
	OIDEncryptionAlgorithmDESEDE3CBC.String(): &cbcBlockCipher{baseBlockCipher: baseBlockCipher{
		keySize:  24,
		newBlock: des.NewTripleDESCipher,
		oid:      OIDEncryptionAlgorithmDESEDE3CBC}, ivSize: des.BlockSize},
	OIDEncryptionAlgorithmAES128CBC.String(): &cbcBlockCipher{baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: aes.NewCipher,
		oid:      OIDEncryptionAlgorithmAES128CBC}, ivSize: aes.BlockSize},
	OIDEncryptionAlgorithmAES192CBC.String(): &cbcBlockCipher{baseBlockCipher: baseBlockCipher{
		keySize:  24,
		newBlock: aes.NewCipher,
		oid:      OIDEncryptionAlgorithmAES192CBC}, ivSize: aes.BlockSize},
	OIDEncryptionAlgorithmAES256CBC.String(): &cbcBlockCipher{baseBlockCipher: baseBlockCipher{
		keySize:  32,
		newBlock: aes.NewCipher,
		oid:      OIDEncryptionAlgorithmAES256CBC}, ivSize: aes.BlockSize},
	OIDEncryptionAlgorithmSM4CBC.String(): &cbcBlockCipher{baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      OIDEncryptionAlgorithmSM4CBC}, ivSize: sm4.BlockSize},
	OIDEncryptionAlgorithmAES128GCM.String(): &gcmBlockCipher{baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: aes.NewCipher,
		oid:      OIDEncryptionAlgorithmAES128GCM}, nonceSize: 12},
	OIDEncryptionAlgorithmAES192GCM.String(): &gcmBlockCipher{baseBlockCipher: baseBlockCipher{
		keySize:  24,
		newBlock: aes.NewCipher,
		oid:      OIDEncryptionAlgorithmAES192GCM}, nonceSize: 12},
	OIDEncryptionAlgorithmAES256GCM.String(): &gcmBlockCipher{baseBlockCipher: baseBlockCipher{
		keySize:  32,
		newBlock: aes.NewCipher,
		oid:      OIDEncryptionAlgorithmAES256GCM}, nonceSize: 12},
	OIDEncryptionAlgorithmSM4GCM.String(): &gcmBlockCipher{baseBlockCipher: baseBlockCipher{
		keySize:  16,
		newBlock: sm4.NewCipher,
		oid:      OIDEncryptionAlgorithmSM4GCM}, nonceSize: 12},
}

type baseBlockCipher struct {
	oid      asn1.ObjectIdentifier
	keySize  int
	newBlock func(key []byte) (cipher.Block, error)
}

func (b *baseBlockCipher) KeySize() int {
	return b.keySize
}

func (b *baseBlockCipher) OID() asn1.ObjectIdentifier {
	return b.oid
}

type ecbBlockCipher struct {
	baseBlockCipher
}

func (ecb *ecbBlockCipher) Encrypt(key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error) {
	block, err := ecb.newBlock(key)
	if err != nil {
		return nil, nil, err
	}
	mode := smcipher.NewECBEncrypter(block)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	encryptionScheme := pkix.AlgorithmIdentifier{
		Algorithm: ecb.oid,
	}

	return &encryptionScheme, ciphertext, nil
}

func (ecb *ecbBlockCipher) Decrypt(key []byte, parameters *asn1.RawValue, ciphertext []byte) ([]byte, error) {
	block, err := ecb.newBlock(key)
	if err != nil {
		return nil, err
	}
	mode := smcipher.NewECBDecrypter(block)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

type cbcBlockCipher struct {
	baseBlockCipher
	ivSize int
}

func (cbc *cbcBlockCipher) Encrypt(key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error) {
	block, err := cbc.newBlock(key)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, block.BlockSize())
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plainText := pkcs7.Pad(plaintext)
	ciphertext := make([]byte, len(plainText))
	mode.CryptBlocks(ciphertext, plainText)

	encryptionScheme := pkix.AlgorithmIdentifier{
		Algorithm:  cbc.oid,
		Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
	}
	return &encryptionScheme, ciphertext, nil
}

func (cbc *cbcBlockCipher) Decrypt(key []byte, parameters *asn1.RawValue, ciphertext []byte) ([]byte, error) {
	block, err := cbc.newBlock(key)
	if err != nil {
		return nil, err
	}

	var iv []byte
	if _, err := asn1.Unmarshal(parameters.FullBytes, &iv); err != nil {
		return nil, errors.New("pkcs7: invalid cipher parameters")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	pkcs7 := padding.NewPKCS7Padding(uint(block.BlockSize()))
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	return pkcs7.Unpad(plaintext)
}

type gcmBlockCipher struct {
	baseBlockCipher
	nonceSize int
}

type gcmParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func (gcm *gcmBlockCipher) Encrypt(key, plaintext []byte) (*pkix.AlgorithmIdentifier, []byte, error) {
	block, err := gcm.newBlock(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.nonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, gcm.nonceSize)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	paramSeq := gcmParameters{
		Nonce:  nonce,
		ICVLen: aead.Overhead(),
	}
	paramBytes, err := asn1.Marshal(paramSeq)
	if err != nil {
		return nil, nil, err
	}
	encryptionAlgorithm := pkix.AlgorithmIdentifier{
		Algorithm: gcm.oid,
		Parameters: asn1.RawValue{
			FullBytes: paramBytes,
		},
	}
	return &encryptionAlgorithm, ciphertext, nil
}

func (gcm *gcmBlockCipher) Decrypt(key []byte, parameters *asn1.RawValue, ciphertext []byte) ([]byte, error) {
	block, err := gcm.newBlock(key)
	if err != nil {
		return nil, err
	}
	params := gcmParameters{}
	_, err = asn1.Unmarshal(parameters.FullBytes, &params)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, len(params.Nonce))
	if err != nil {
		return nil, err
	}
	if params.ICVLen != aead.Overhead() {
		return nil, errors.New("pkcs7: invalid tag size")
	}

	return aead.Open(nil, params.Nonce, ciphertext, nil)
}
