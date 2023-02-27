package pkcs7

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	smcipher "github.com/emmansun/gmsm/cipher"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/smx509"
)

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type encryptedData struct {
	Version              int
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

func (data envelopedData) GetRecipient(cert *smx509.Certificate) *recipientInfo {
	for _, recp := range data.RecipientInfos {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return &recp
		}
	}
	return nil
}

func (data envelopedData) GetEncryptedContentInfo() *encryptedContentInfo {
	return &data.EncryptedContentInfo
}

type EncryptionAlgorithm int

const (
	// EncryptionAlgorithmDESCBC is the DES CBC encryption algorithm
	EncryptionAlgorithmDESCBC EncryptionAlgorithm = iota

	// EncryptionAlgorithmDESEDE3CBC is the 3DES CBC encryption algorithm
	EncryptionAlgorithmDESEDE3CBC

	// EncryptionAlgorithmAES128CBC is the AES 128 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES128CBC

	// EncryptionAlgorithmAES256CBC is the AES 256 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use AES GCM instead.
	EncryptionAlgorithmAES256CBC

	// EncryptionAlgorithmAES128GCM is the AES 128 bits with GCM encryption algorithm
	EncryptionAlgorithmAES128GCM

	// EncryptionAlgorithmAES256GCM is the AES 256 bits with GCM encryption algorithm
	EncryptionAlgorithmAES256GCM

	// EncryptionAlgorithmSM4CBC is the SM4 128 bits with CBC encryption algorithm
	// Avoid this algorithm unless required for interoperability; use SM4 GCM instead.
	EncryptionAlgorithmSM4CBC

	// EncryptionAlgorithmSM4GCM is the SM4 128 bits with GCM encryption algorithm
	EncryptionAlgorithmSM4GCM

	// EncryptionAlgorithmSM4ECB is the SM4 128 bits with ECB encryption algorithm
	EncryptionAlgorithmSM4ECB

	// EncryptionAlgorithmSM4 is same as EncryptionAlgorithmSM4ECB
	EncryptionAlgorithmSM4
)

// ErrUnsupportedEncryptionAlgorithm is returned when attempting to encrypt
// content with an unsupported algorithm.
var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC, AES-CBC, AES-GCM, SM4-CBC and SM4-GCM supported")

// ErrPSKNotProvided is returned when attempting to encrypt
// using a PSK without actually providing the PSK.
var ErrPSKNotProvided = errors.New("pkcs7: cannot encrypt content: PSK not provided")

const nonceSize = 12

type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func encryptGCM(alg EncryptionAlgorithm, content []byte, key []byte) ([]byte, *encryptedContentInfo, error) {
	var keyLen int
	var algID asn1.ObjectIdentifier
	var newBlock func(key []byte) (cipher.Block, error)
	switch alg {
	case EncryptionAlgorithmAES128GCM:
		keyLen = 16
		algID = OIDEncryptionAlgorithmAES128GCM
		newBlock = aes.NewCipher
	case EncryptionAlgorithmAES256GCM:
		keyLen = 32
		algID = OIDEncryptionAlgorithmAES256GCM
		newBlock = aes.NewCipher
	case EncryptionAlgorithmSM4GCM:
		keyLen = 16
		algID = OIDEncryptionAlgorithmSM4GCM
		newBlock = sm4.NewCipher
	default:
		return nil, nil, fmt.Errorf("pkcs7: invalid ContentEncryptionAlgorithm in encryptAES/SM4 GCM: %d", alg)
	}
	if key == nil {
		// Create key
		key = make([]byte, keyLen)

		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create nonce
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt content
	block, err := newBlock(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, content, nil)

	// Prepare ASN.1 Encrypted Content Info
	paramSeq := aesGCMParameters{
		Nonce:  nonce,
		ICVLen: gcm.Overhead(),
	}

	paramBytes, err := asn1.Marshal(paramSeq)
	if err != nil {
		return nil, nil, err
	}

	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: algID,
			Parameters: asn1.RawValue{
				Tag:   asn1.TagSequence,
				Bytes: paramBytes,
				IsCompound: true,
			},
		},
		EncryptedContent: marshalEncryptedContent(ciphertext),
	}

	return key, &eci, nil
}

func encryptCBC(alg EncryptionAlgorithm, content []byte, key []byte) ([]byte, *encryptedContentInfo, error) {
	var keyLen int
	var algID asn1.ObjectIdentifier
	var blockSize int = 16
	var newBlock func(key []byte) (cipher.Block, error)
	switch alg {
	case EncryptionAlgorithmDESCBC:
		keyLen = 8
		blockSize = des.BlockSize
		algID = OIDEncryptionAlgorithmDESCBC
		newBlock = des.NewCipher
	case EncryptionAlgorithmDESEDE3CBC:
		keyLen = 24
		blockSize = des.BlockSize
		algID = OIDEncryptionAlgorithmDESEDE3CBC
		newBlock = des.NewTripleDESCipher
	case EncryptionAlgorithmAES128CBC:
		keyLen = 16
		algID = OIDEncryptionAlgorithmAES128CBC
		newBlock = aes.NewCipher
	case EncryptionAlgorithmAES256CBC:
		keyLen = 32
		algID = OIDEncryptionAlgorithmAES256CBC
		newBlock = aes.NewCipher
	case EncryptionAlgorithmSM4CBC:
		keyLen = 16
		algID = OIDEncryptionAlgorithmSM4CBC
		newBlock = sm4.NewCipher
	default:
		return nil, nil, fmt.Errorf("pkcs7: invalid ContentEncryptionAlgorithm in encrypt DES/AES/SM4 CBC: %d", alg)
	}

	if key == nil {
		// Create AES key
		key = make([]byte, keyLen)

		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
	}

	// Create CBC IV
	iv := make([]byte, blockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := newBlock(key)
	if err != nil {
		return nil, nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	if err != nil {
		return nil, nil, err
	}
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  algID,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

func encryptECB(alg EncryptionAlgorithm, content []byte, key []byte) ([]byte, *encryptedContentInfo, error) {
	var keyLen int
	var algID asn1.ObjectIdentifier
	var newBlock func(key []byte) (cipher.Block, error)
	switch alg {
	case EncryptionAlgorithmSM4ECB:
		keyLen = 16
		algID = OIDEncryptionAlgorithmSM4ECB
		newBlock = sm4.NewCipher
	case EncryptionAlgorithmSM4:
		keyLen = 16
		algID = OIDEncryptionAlgorithmSM4
		newBlock = sm4.NewCipher
	default:
		return nil, nil, fmt.Errorf("pkcs7: invalid ContentEncryptionAlgorithm in encrypt SM4 ECB: %d", alg)
	}

	if key == nil {
		// Create AES key
		key = make([]byte, keyLen)

		_, err := rand.Read(key)
		if err != nil {
			return nil, nil, err
		}
	}

	// Encrypt padded content
	block, err := newBlock(key)
	if err != nil {
		return nil, nil, err
	}

	mode := smcipher.NewECBEncrypter(block)
	cyphertext := make([]byte, len(content))
	mode.CryptBlocks(cyphertext, content)

	// Prepare ASN.1 Encrypted Content Info
	eci := encryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: algID,
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

// Encrypt creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
//
// The algorithm used to perform encryption is determined by the argument alg
//
// TODO(fullsailor): Add support for encrypting content with other algorithms
func Encrypt(alg EncryptionAlgorithm, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	return encrypt(alg, content, recipients, false)
}

// EncryptSM creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
// The OIDs use GM/T 0010 - 2012 set
//
// The algorithm used to perform encryption is determined by the argument alg
//
func EncryptSM(alg EncryptionAlgorithm, content []byte, recipients []*smx509.Certificate) ([]byte, error) {
	return encrypt(alg, content, recipients, true)
}

func encrypt(alg EncryptionAlgorithm, content []byte, recipients []*smx509.Certificate, isSM bool) ([]byte, error) {
	var eci *encryptedContentInfo
	var key []byte
	var err error

	// Apply chosen symmetric encryption method
	switch alg {
	case EncryptionAlgorithmDESCBC, EncryptionAlgorithmDESEDE3CBC, EncryptionAlgorithmSM4CBC, EncryptionAlgorithmAES128CBC, EncryptionAlgorithmAES256CBC:
		key, eci, err = encryptCBC(alg, content, nil)
	case EncryptionAlgorithmSM4GCM, EncryptionAlgorithmAES128GCM, EncryptionAlgorithmAES256GCM:
		key, eci, err = encryptGCM(alg, content, nil)
	case EncryptionAlgorithmSM4, EncryptionAlgorithmSM4ECB:
		key, eci, err = encryptECB(alg, content, nil)
	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	if isSM {
		eci.ContentType = SM2OIDData
	}

	// Prepare each recipient's encrypted cipher key
	recipientInfos := make([]recipientInfo, len(recipients))
	for i, recipient := range recipients {
		encrypted, err := encryptKey(key, recipient)
		if err != nil {
			return nil, err
		}
		ias, err := cert2issuerAndSerial(recipient)
		if err != nil {
			return nil, err
		}
		var keyEncryptionAlgorithm asn1.ObjectIdentifier = OIDEncryptionAlgorithmRSA
		if recipient.SignatureAlgorithm == smx509.SM2WithSM3 {
			keyEncryptionAlgorithm = OIDKeyEncryptionAlgorithmSM2
		} else if isSM {
			return nil, errors.New("pkcs7: Shangmi does not support RSA")
		}

		info := recipientInfo{
			Version:               0,
			IssuerAndSerialNumber: ias,
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: keyEncryptionAlgorithm,
			},
			EncryptedKey: encrypted,
		}
		recipientInfos[i] = info
	}

	// Prepare envelope content
	envelope := envelopedData{
		EncryptedContentInfo: *eci,
		Version:              0,
		RecipientInfos:       recipientInfos,
	}

	if isSM {
		envelope.EncryptedContentInfo.ContentType = SM2OIDData
	}

	innerContent, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: OIDEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	if isSM {
		wrapper.ContentType = SM2OIDEnvelopedData
	}

	return asn1.Marshal(wrapper)
}

// EncryptUsingPSK creates and returns an encrypted data PKCS7 structure,
// encrypted using caller provided pre-shared secret.
func EncryptUsingPSK(alg EncryptionAlgorithm, content []byte, key []byte) ([]byte, error) {
	return encryptUsingPSK(false, alg, content, key)
}

// EncryptSMUsingPSK creates and returns an encrypted data PKCS7 structure,
// encrypted using caller provided pre-shared secret.
// This method uses China Standard OID
func EncryptSMUsingPSK(alg EncryptionAlgorithm, content []byte, key []byte) ([]byte, error) {
	return encryptUsingPSK(true, alg, content, key)
}

func encryptUsingPSK(isSM bool, alg EncryptionAlgorithm, content []byte, key []byte) ([]byte, error) {
	var eci *encryptedContentInfo
	var err error

	if key == nil {
		return nil, ErrPSKNotProvided
	}

	// Apply chosen symmetric encryption method
	switch alg {
	case EncryptionAlgorithmDESCBC:
		_, eci, err = encryptCBC(alg, content, key)

	case EncryptionAlgorithmSM4GCM, EncryptionAlgorithmAES128GCM, EncryptionAlgorithmAES256GCM:
		_, eci, err = encryptGCM(alg, content, key)

	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	// Prepare encrypted-data content
	ed := encryptedData{
		Version:              0,
		EncryptedContentInfo: *eci,
	}
	innerContent, err := asn1.Marshal(ed)
	if err != nil {
		return nil, err
	}

	var contentType asn1.ObjectIdentifier = OIDEncryptedData
	if isSM {
		contentType = SM2OIDEncryptedData
	}
	// Prepare outer payload structure
	wrapper := contentInfo{
		ContentType: contentType,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
	asn1Content, _ := asn1.Marshal(content)
	return asn1.RawValue{Tag: 0, Class: 2, Bytes: asn1Content, IsCompound: true}
}

func encryptKey(key []byte, recipient *smx509.Certificate) ([]byte, error) {
	if pub, ok := recipient.PublicKey.(*rsa.PublicKey); ok {
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	}
	if pub, ok := recipient.PublicKey.(*ecdsa.PublicKey); ok && pub.Curve == sm2.P256() {
		return sm2.EncryptASN1(rand.Reader, pub, key)
	}
	return nil, ErrUnsupportedAlgorithm
}

func pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := blocklen - (len(data) % blocklen)
	if padlen == 0 {
		padlen = blocklen
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}
