package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"

	smcipher "github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/smx509"
)

// ErrUnsupportedAlgorithm tells you when our quick dev assumptions have failed
var ErrUnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, SM2, DES, DES-EDE3, AES and SM4 supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is NOT a decryptable data type")

type decryptable interface {
	GetRecipient(cert *smx509.Certificate) *recipientInfo
	GetEncryptedContentInfo() *encryptedContentInfo
}

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *smx509.Certificate, pkey crypto.PrivateKey) ([]byte, error) {
	decryptableData, ok := p7.raw.(decryptable)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := decryptableData.GetRecipient(cert)
	if recipient == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}

	switch pkey := pkey.(type) {
	case crypto.Decrypter:
		// Generic case to handle anything that provides the crypto.Decrypter interface.
		contentKey, err := pkey.Decrypt(rand.Reader, recipient.EncryptedKey, nil)
		if err != nil {
			return nil, err
		}
		return decryptableData.GetEncryptedContentInfo().decrypt(contentKey)
	}
	return nil, ErrUnsupportedAlgorithm
}

// DecryptUsingPSK decrypts encrypted data using caller provided
// pre-shared secret
func (p7 *PKCS7) DecryptUsingPSK(key []byte) ([]byte, error) {
	data, ok := p7.raw.(encryptedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	return data.EncryptedContentInfo.decrypt(key)
}

func (eci encryptedContentInfo) getCiphertext() (ciphertext []byte) {
	// EncryptedContent can either be constructed of multple OCTET STRINGs
	// or _be_ a tagged OCTET STRING
	if eci.EncryptedContent.IsCompound {
		// Complex case to concat all of the children OCTET STRINGs
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
		}
		ciphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the cyphertext
		ciphertext = eci.EncryptedContent.Bytes
	}
	return
}

func (eci encryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	if !alg.Equal(OIDEncryptionAlgorithmDESCBC) &&
		!alg.Equal(OIDEncryptionAlgorithmDESEDE3CBC) &&
		!alg.Equal(OIDEncryptionAlgorithmAES256CBC) &&
		!alg.Equal(OIDEncryptionAlgorithmAES128CBC) &&
		!alg.Equal(OIDEncryptionAlgorithmSM4) &&
		!alg.Equal(OIDEncryptionAlgorithmSM4ECB) &&
		!alg.Equal(OIDEncryptionAlgorithmSM4CBC) &&
		!alg.Equal(OIDEncryptionAlgorithmAES128GCM) &&
		!alg.Equal(OIDEncryptionAlgorithmSM4GCM) &&
		!alg.Equal(OIDEncryptionAlgorithmAES256GCM) {
		return nil, ErrUnsupportedAlgorithm
	}

	ciphertext := eci.getCiphertext()

	var block cipher.Block
	var err error

	switch {
	case alg.Equal(OIDEncryptionAlgorithmDESCBC):
		block, err = des.NewCipher(key)
	case alg.Equal(OIDEncryptionAlgorithmDESEDE3CBC):
		block, err = des.NewTripleDESCipher(key)
	case alg.Equal(OIDEncryptionAlgorithmSM4GCM), alg.Equal(OIDEncryptionAlgorithmSM4CBC), alg.Equal(OIDEncryptionAlgorithmSM4), alg.Equal(OIDEncryptionAlgorithmSM4ECB):
		block, err = sm4.NewCipher(key)
	case alg.Equal(OIDEncryptionAlgorithmAES256CBC), alg.Equal(OIDEncryptionAlgorithmAES256GCM):
		fallthrough
	case alg.Equal(OIDEncryptionAlgorithmAES128GCM), alg.Equal(OIDEncryptionAlgorithmAES128CBC):
		block, err = aes.NewCipher(key)
	}

	if err != nil {
		return nil, err
	}

	var iv []byte
	if alg.Equal(OIDEncryptionAlgorithmSM4GCM) || alg.Equal(OIDEncryptionAlgorithmAES128GCM) || alg.Equal(OIDEncryptionAlgorithmAES256GCM) {
		params := aesGCMParameters{}
		paramBytes := eci.ContentEncryptionAlgorithm.Parameters.Bytes

		_, err := asn1.Unmarshal(paramBytes, &params)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		if len(params.Nonce) != gcm.NonceSize() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}
		if params.ICVLen != gcm.Overhead() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}

		plaintext, err := gcm.Open(nil, params.Nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	} else if alg.Equal(OIDEncryptionAlgorithmSM4ECB) || alg.Equal(OIDEncryptionAlgorithmSM4) {
		mode := smcipher.NewECBDecrypter(block)
		plaintext := make([]byte, len(ciphertext))
		mode.CryptBlocks(plaintext, ciphertext)
		return plaintext, nil
	}
	iv = eci.ContentEncryptionAlgorithm.Parameters.Bytes
	if len(iv) != block.BlockSize() {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)
	if plaintext, err = unpad(plaintext, mode.BlockSize()); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}
