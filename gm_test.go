package pkcs7

import (
	"testing"
)

// from https://www.gmssl.cn/gmssl/index.jsp, just have certificates in SignedData content
var certificateChainGMSSL = `-----BEGIN PKCS7-----
MIID6wYJKoZIhvcNAQcCoIID3DCCA9gCAQExADALBgkqhkiG9w0BBwGgggPAMIIB
zTCCAXCgAwIBAgIGAXKnMKNyMAwGCCqBHM9VAYN1BQAwSTELMAkGA1UEBhMCQ04x
DjAMBgNVBAoTBUdNU1NMMRAwDgYDVQQLEwdQS0kvU00yMRgwFgYDVQQDEw9Sb290
Q0EgZm9yIFRlc3QwIhgPMjAxNTEyMzExNjAwMDBaGA8yMDM1MTIzMDE2MDAwMFow
STELMAkGA1UEBhMCQ04xDjAMBgNVBAoTBUdNU1NMMRAwDgYDVQQLEwdQS0kvU00y
MRgwFgYDVQQDEw9Sb290Q0EgZm9yIFRlc3QwWTATBgcqhkjOPQIBBggqgRzPVQGC
LQNCAATj+apYlL+ddWXZ7+mFZXZJGbcJFXUN+Fszz6humeyWZP4qEEr2N0+aZdwo
/21ft232yo0jPLzdscKB261zSQXSoz4wPDAZBgNVHQ4EEgQQnGnsD7oaOcWv6CTr
spwSBDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIAxjAMBggqgRzPVQGD
dQUAA0kAMEYCIQCEnW5BlQh0vmsOLxSoXYc/7zs++wWyFc1tnBHENR4ElwIhAI1L
wu6in1ruflZhzseWulXwcITf3bm/Y5X1g1XFWQUHMIIB6zCCAY+gAwIBAgIGAXKn
MMauMAwGCCqBHM9VAYN1BQAwSTELMAkGA1UEBhMCQ04xDjAMBgNVBAoTBUdNU1NM
MRAwDgYDVQQLEwdQS0kvU00yMRgwFgYDVQQDEw9Sb290Q0EgZm9yIFRlc3QwIhgP
MjAxNTEyMzExNjAwMDBaGA8yMDM1MTIzMDE2MDAwMFowSzELMAkGA1UEBhMCQ04x
DjAMBgNVBAoTBUdNU1NMMRAwDgYDVQQLEwdQS0kvU00yMRowGAYDVQQDExFNaWRk
bGVDQSBmb3IgVGVzdDBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABA4uB1fiqJjs
1uR6bFIrtxvLFuoU0x+uPPxrslzodyTG1Mj9dJpm4AUjT9q2bL4cj7H73qWJNpwA
rnZr7fCc3A2jWzBZMBsGA1UdIwQUMBKAEJxp7A+6GjnFr+gk67KcEgQwGQYDVR0O
BBIEEPl/VbQnlDNiplbKb8xdGv8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAMYwDAYIKoEcz1UBg3UFAANIADBFAiA31tn0qKz6G0YgGjWd6/ULMyqfTzoL
82Y7EkvxbOpX/AIhAKCJYkDp62cvbKvj/Njc2dIe5BN+DGhO5JOhIyo4oWE3MQA=
-----END PKCS7-----`

func TestParseSM2CertificateChain(t *testing.T) {
	fixture := UnmarshalTestFixture(certificateChainGMSSL)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Fatal(err)
	}
	if len(p7.Certificates) != 2 {
		t.Errorf("expected 2, but got %d", len(p7.Certificates))
	}
	err = p7.Certificates[1].CheckSignatureFrom(p7.Certificates[0])
	if err != nil {
		t.Fatal(err)
	}
}
