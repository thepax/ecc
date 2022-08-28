package ecc

import (
    "bytes"
    "crypto/ecdsa"
    "crypto/sha512"
    "io"
    "golang.org/x/crypto/hkdf"
    "golang.org/x/crypto/scrypt"
)

// GenerateKey generates ECDSA key from specified Curve.
func GenerateKey(c *Curve, rr io.Reader) (*ecdsa.PrivateKey, error) {
    return ecdsa.GenerateKey(c.Curve(), rr)
}

func GenerateCoolKey(c *Curve, rr io.Reader) (*ecdsa.PrivateKey, error) {
    for {
	priv, err := ecdsa.GenerateKey(c.Curve(), rr)
	if err != nil {
	    return nil, err
	}
	short, err := MarshalShortPrivateKey(priv)
	if err != nil {
	    return nil, err
	}
	if bytes.IndexAny(short, "_-+/") >= 0 {
	    continue
	}
	short, err = MarshalShortPublicKey(&priv.PublicKey)
	if err != nil {
	    return nil, err
	}
	if bytes.IndexAny(short, "_-+/") < 0 {
	    return priv, nil
	}
    }
}

func GenerateKeyFromData(c *Curve, data []byte, salt []byte) (*ecdsa.PrivateKey, error) {
    return GenerateKey(c, hkdf.New(sha512.New, data, salt, nil))
}

type SCryptOpts struct {
    Curve *Curve
    N int
    R int
    P int
    Salt []byte
}

func NewDefaultSCryptOpts() *SCryptOpts {
    return &SCryptOpts{
	Curve: LookupCurve("secp521r1"),
	N: 1<<20,
	R: 8,
	P: 1,
	Salt: nil,
    }
}

func GenerateKeyFromPassword(password []byte, scryptOpts *SCryptOpts) (*ecdsa.PrivateKey, error) {
    if scryptOpts == nil {
	scryptOpts = NewDefaultSCryptOpts()
    }
    key, err := scrypt.Key(password, scryptOpts.Salt, scryptOpts.N, scryptOpts.R, scryptOpts.P, 1048576)
    if err != nil {
	return nil, err
    }
    return GenerateKeyFromData(scryptOpts.Curve, key, scryptOpts.Salt)
}
