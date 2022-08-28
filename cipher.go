package ecc

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/asn1"
    "strings"
    "github.com/pkg/errors"
    "golang.org/x/crypto/chacha20poly1305"
)

type Cipher struct {
    Name string
    Description string
    OID asn1.ObjectIdentifier
    KeySize int
    New func(key []byte) (cipher.AEAD, error)
    KDF *KDF
}

// Suppported ciphers
var Ciphers = []*Cipher{
    {
	Name: "aes-128-gcm",
	OID: asn1.ObjectIdentifier{2,16,840,1,101,3,4,1,6},
	KeySize: 16,
	New: newAESGCM,
	KDF: KDFs["hkdf-sha256"],
    },
    {
	Name: "aes-192-gcm",
	OID: asn1.ObjectIdentifier{2,16,840,1,101,3,4,1,26},
	KeySize: 24,
	New: newAESGCM,
	KDF: KDFs["hkdf-sha256"],
    },
    {
	Name: "aes-256-gcm",
	OID: asn1.ObjectIdentifier{2,16,840,1,101,3,4,1,46},
	KeySize: 32,
	New: newAESGCM,
	KDF: KDFs["hkdf-sha384"],
    },
    {
	Name: "chacha20-poly1305",
	OID: asn1.ObjectIdentifier{1,2,840,113549,1,9,16,3,18},
	KeySize: 32,
	New: chacha20poly1305.New,
	KDF: KDFs["hkdf-sha384"],
    },
}

func LookupCipher(name string) *Cipher {
    name = strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(name), "-", ""), "_", "")
    for _, c := range Ciphers {
	if strings.ReplaceAll(c.Name, "-", "") == name {
	    return c
	}
    }
    return nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
	return nil, errors.Wrapf(err, "init AES")
    }
    aead, err := cipher.NewGCM(block)
    if err != nil {
	return nil, errors.Wrapf(err, "init GCM")
    }
    return aead, nil
}
