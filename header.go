package ecc

import (
    "crypto/ecdsa"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/x509"
    "encoding/asn1"
    "io"
    "github.com/pkg/errors"
)

// The ecc magic sequence.
var Magic = []byte{0x13, 0x04, 0x65, 0x63, 0x63, 0x31}

// IsMagic returns true if buf starts with an ecc stream.
func IsMagic(buf []byte) bool {
    return len(buf) >= 6 &&
	buf[0] == 0x13 && buf[1] == 0x04 &&
	buf[2] == 0x65 && buf[3] == 0x63 && buf[4] == 0x63 &&
	buf[5] == 0x31
}

func MagicVersion(buf []byte) (int, error) {
    if !IsMagic(buf) {
	return -1, ErrBadMagic
    }
    return int(buf[5] - 0x30), nil
}

type eccHeader struct {
    PKIXPublicKey []byte
    Ciphers []asn1.ObjectIdentifier
    Signature []byte
}

func newHeader(pub *ecdsa.PublicKey, ciphers ...asn1.ObjectIdentifier) (*eccHeader, error) {
    pkixPub, err := x509.MarshalPKIXPublicKey(pub)
    if err != nil {
        return nil, err
    }
    return &eccHeader{
	PKIXPublicKey: pkixPub,
	Ciphers: ciphers,
    }, nil
}

func unmarshalHeader(buf []byte) (*eccHeader, error) {
    header := &eccHeader{}
    if _, err := asn1.Unmarshal(buf, header); err != nil {
	return nil, errors.New("invalid header")
    }
    return header, nil
}

func (h *eccHeader) PublicKey() (*ecdsa.PublicKey, error) {
    pub, err := x509.ParsePKIXPublicKey(h.PKIXPublicKey)
    if err != nil {
	return nil, err
    }
    if ecdsaPub, ok := pub.(*ecdsa.PublicKey); ok {
	return ecdsaPub, nil
    }
    return nil, ErrInvalidKeyType
}

func (h *eccHeader) Cipher() (*Cipher, error) {
    for _, oid := range h.Ciphers {
	for _, c := range Ciphers {
	    if c.OID.Equal(oid) {
		return c, nil
	    }
	}
    }
    return nil, ErrUnknownEncryption
}

func (h *eccHeader) KDF() (*KDF, error) {
    for _, oid := range h.Ciphers {
	for _, kdf := range KDFs {
	    if kdf.OID.Equal(oid) {
		return kdf, nil
	    }
	}
    }
    return nil, ErrUnknownKDF
}

func (h *eccHeader) Marshal() ([]byte, error) {
    return asn1.Marshal(*h)
}

func (h *eccHeader) Sign(priv *ecdsa.PrivateKey, rr io.Reader) (err error) {
    var hash []byte
    switch {
    case priv.Curve.Params().BitSize <= 224:
	h.Ciphers = append(h.Ciphers, oidEcdsaWithSha224)
	sum := sha256.Sum224(h.PKIXPublicKey)
	hash = sum[:]
    case priv.Curve.Params().BitSize <= 256:
	h.Ciphers = append(h.Ciphers, oidEcdsaWithSha256)
	sum := sha256.Sum256(h.PKIXPublicKey)
	hash = sum[:]
    case priv.Curve.Params().BitSize <= 384:
	h.Ciphers = append(h.Ciphers, oidEcdsaWithSha384)
	sum := sha512.Sum384(h.PKIXPublicKey)
	hash = sum[:]
    default:
	h.Ciphers = append(h.Ciphers, oidEcdsaWithSha512)
	sum := sha512.Sum512(h.PKIXPublicKey)
	hash = sum[:]
    }
    h.Signature, err = ecdsa.SignASN1(rr, priv, hash)
    return err
}

func (h *eccHeader) Verify(pub *ecdsa.PublicKey) error {
    if h.Signature == nil {
	return ErrNotSigned
    }
    for _, cipher := range h.Ciphers {
	if cipher.Equal(oidEcdsaWithSha224) {
	    sum := sha256.Sum224(h.PKIXPublicKey)
	    if ecdsa.VerifyASN1(pub, sum[:], h.Signature) {
		return nil
	    }
	    return ErrVerifyFailed
	}
	if cipher.Equal(oidEcdsaWithSha256) {
	    sum := sha256.Sum256(h.PKIXPublicKey)
	    if ecdsa.VerifyASN1(pub, sum[:], h.Signature) {
		return nil
	    }
	    return ErrVerifyFailed
	}
	if cipher.Equal(oidEcdsaWithSha384) {
	    sum := sha512.Sum384(h.PKIXPublicKey)
	    if ecdsa.VerifyASN1(pub, sum[:], h.Signature) {
		return nil
	    }
	    return ErrVerifyFailed
	}
	if cipher.Equal(oidEcdsaWithSha512) {
	    sum := sha512.Sum512(h.PKIXPublicKey)
	    if ecdsa.VerifyASN1(pub, sum[:], h.Signature) {
		return nil
	    }
	    return ErrVerifyFailed
	}
    }
    return ErrNotSigned
}
