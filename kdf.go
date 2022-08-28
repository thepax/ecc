package ecc

import (
    "crypto/ecdsa"
    "encoding/asn1"
    "crypto/sha256"
    "crypto/sha512"
    "io"
    "math/big"
    "github.com/pkg/errors"
    "golang.org/x/crypto/hkdf"
)

type KDF struct {
    Name string
    Description string
    OID asn1.ObjectIdentifier
    HashSize int
    New func(secret []byte) io.Reader
}

// Supported Key Derivation Functions
// (see RFC8619)
var KDFs = map[string]*KDF {
    "hkdf-sha256": &KDF{
	Name: "hkdf-sha256",
	Description: "HMAC-based Key Derivation Function with SHA256",
	OID: asn1.ObjectIdentifier{1,2,840,113549,1,9,16,3,28},
	HashSize: 32,
	New: func(secret []byte) io.Reader {
	    return hkdf.New(sha256.New, secret, nil, nil)
	},
    },
    "hkdf-sha384": &KDF{
	Name: "hkdf-sha384",
	Description: "HMAC-based Key Derivation Function with SHA384",
	OID: asn1.ObjectIdentifier{1,2,840,113549,1,9,16,3,29},
	HashSize: 48,
	New: func(secret []byte) io.Reader {
	    return hkdf.New(sha512.New384, secret, nil, nil)
	},
    },
    "hkdf-sha512": &KDF{
	Name: "hkdf-sha512",
	Description: "HMAC-based Key Derivation Function with SHA512",
	OID: asn1.ObjectIdentifier{1,2,840,113549,1,9,16,3,30},
	HashSize: 64,
	New: func(secret []byte) io.Reader {
	    return hkdf.New(sha512.New, secret, nil, nil)
	},
    },
}

// Derives keys for symmetric encryption/decryption using ECDH.
func DeriveKey(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, pub2 *ecdsa.PublicKey, size int, kdf *KDF) ([]byte, error) {
    sx, sy := pub.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
    var secret = struct {
	PX *big.Int
	PY *big.Int
	SX *big.Int
	SY *big.Int
    }{ pub2.X, pub2.Y, sx, sy }
    s, err := asn1.Marshal(secret)
    if err != nil {
	return nil, errors.Wrapf(err, "marshal secret")
    }
    kdfr := kdf.New(s)
    key := make([]byte, size)
    _, err = io.ReadFull(kdfr, key)
    if err != nil {
	return nil, errors.New("cannot derive key")
    }
    return key, nil
}
