package pkcs7

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"testing"

	"github.com/emmansun/gmsm/smx509"
)

func TestEncrypt(t *testing.T) {
	modes := []asn1.ObjectIdentifier{
		OIDEncryptionAlgorithmDESCBC,
		OIDEncryptionAlgorithmDESEDE3CBC,
		OIDEncryptionAlgorithmSM4CBC,
		OIDEncryptionAlgorithmSM4GCM,
		OIDEncryptionAlgorithmAES128CBC,
		OIDEncryptionAlgorithmAES192CBC,
		OIDEncryptionAlgorithmAES256CBC,
		OIDEncryptionAlgorithmAES128GCM,
		OIDEncryptionAlgorithmAES192GCM,
		OIDEncryptionAlgorithmAES256GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		smx509.SM2WithSM3,
	}
	for _, mode := range modes {
		for _, sigalg := range sigalgs {
			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := Encrypt(mode, plaintext, []*smx509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestEncryptSM(t *testing.T) {
	modes := []asn1.ObjectIdentifier{
		OIDEncryptionAlgorithmSM4CBC,
		OIDEncryptionAlgorithmSM4GCM,
	}
	sigalgs := []x509.SignatureAlgorithm{
		smx509.SM2WithSM3,
	}
	for _, mode := range modes {
		for _, sigalg := range sigalgs {
			plaintext := []byte("Hello Secret World!")
			cert, err := createTestCertificate(sigalg)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := EncryptSM(mode, plaintext, []*smx509.Certificate{cert.Certificate})
			if err != nil {
				t.Fatal(err)
			}
			pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: encrypted})
			p7, err := Parse(encrypted)
			if err != nil {
				t.Fatalf("cannot Parse encrypted result: %s", err)
			}
			result, err := p7.Decrypt(cert.Certificate, *cert.PrivateKey)
			if err != nil {
				t.Fatalf("cannot Decrypt encrypted result: %s", err)
			}
			if !bytes.Equal(plaintext, result) {
				t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
			}
		}
	}
}

func TestEncryptUsingPSK(t *testing.T) {
	modes := []asn1.ObjectIdentifier{
		OIDEncryptionAlgorithmDESCBC,
		OIDEncryptionAlgorithmSM4GCM,
		OIDEncryptionAlgorithmAES128GCM,
	}

	for _, mode := range modes {
		plaintext := []byte("Hello Secret World!")
		var key []byte

		switch {
		case mode.Equal(OIDEncryptionAlgorithmDESCBC):
			key = []byte("64BitKey")
		case mode.Equal(OIDEncryptionAlgorithmSM4GCM), mode.Equal(OIDEncryptionAlgorithmAES128GCM):
			key = []byte("128BitKey4AESGCM")
		}
		ciphertext, err := EncryptUsingPSK(mode, plaintext, key)
		if err != nil {
			t.Fatal(err)
		}

		p7, _ := Parse(ciphertext)
		result, err := p7.DecryptUsingPSK(key)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		if !bytes.Equal(plaintext, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}

func TestEncryptSMUsingPSK(t *testing.T) {
	modes := []asn1.ObjectIdentifier{
		OIDEncryptionAlgorithmDESCBC,
		OIDEncryptionAlgorithmSM4GCM,
		OIDEncryptionAlgorithmAES128GCM,
	}

	for _, mode := range modes {
		plaintext := []byte("Hello Secret World!")
		var key []byte

		switch {
		case mode.Equal(OIDEncryptionAlgorithmDESCBC):
			key = []byte("64BitKey")
		case mode.Equal(OIDEncryptionAlgorithmSM4GCM), mode.Equal(OIDEncryptionAlgorithmAES128GCM):
			key = []byte("128BitKey4AESGCM")
		}
		ciphertext, err := EncryptSMUsingPSK(mode, plaintext, key)
		if err != nil {
			t.Fatal(err)
		}

		p7, _ := Parse(ciphertext)
		result, err := p7.DecryptUsingPSK(key)
		if err != nil {
			t.Fatalf("cannot Decrypt encrypted result: %s", err)
		}
		if !bytes.Equal(plaintext, result) {
			t.Errorf("encrypted data does not match plaintext:\n\tExpected: %s\n\tActual: %s", plaintext, result)
		}
	}
}
