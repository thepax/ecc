// Package ecc implements basic Elliptic Curve Cryptography functions.
// 
package ecc

import (
    "encoding/asn1"
    "github.com/pkg/errors"
)

// Default chunk size for encrypted streams.
const DefaultChunkSize = 65536

var (
    ErrBadEncoding = errors.New("bad encoding")
    ErrBadMagic = errors.New("bad magic")
    ErrInvalidCipher = errors.New("invalid cipher")
    ErrInvalidKey = errors.New("invalid key")
    ErrInvalidKeyType = errors.New("invalid key type")
    ErrNotSigned = errors.New("not signed")
    ErrUnableToLoadKey = errors.New("unable to load key")
    ErrUnknownEncryption = errors.New("unknown encryption")
    ErrUnknownKDF = errors.New("unknown key derivation function")
    ErrUnsupportedCurve = errors.New("unsupported curve")
    ErrVerifyFailed = errors.New("verify failed")
)

var (
    oidEcdsaWithSha224 = asn1.ObjectIdentifier{1,2,840,10045,4,3,1}
    oidEcdsaWithSha256 = asn1.ObjectIdentifier{1,2,840,10045,4,3,2}
    oidEcdsaWithSha384 = asn1.ObjectIdentifier{1,2,840,10045,4,3,3}
    oidEcdsaWithSha512 = asn1.ObjectIdentifier{1,2,840,10045,4,3,4}
)
