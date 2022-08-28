package ecc

import (
    "bytes"
    "crypto/ecdsa"
    "crypto/x509"
    "encoding/pem"
    "io"
    "os"
    "github.com/pkg/errors"
)

func WritePEM(key interface{}, w io.Writer) error {
    switch key.(type) {
    case *ecdsa.PrivateKey:
	der, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
	if err != nil {
	    return errors.Wrapf(err, "write private key PEM: marshal EC private key")
	}
	return errors.Wrapf(pem.Encode(w, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), "write private key PEM: encode")
    case *ecdsa.PublicKey:
	der, err := x509.MarshalPKIXPublicKey(key.(*ecdsa.PublicKey))
	if err != nil {
	    return errors.Wrapf(err, "write PEM: marshal EC public key")
	}
	return errors.Wrapf(pem.Encode(w, &pem.Block{Type: "PUBLIC KEY", Bytes: der}), "write PEM: encode")
    }
    return ErrInvalidKeyType
}

// ReadPEM reads either ecdsa.PrivateKey or ecdsa.PublicKey from io.Reader.
// ReadPEM returns ErrUnableToLoadKey if io.Reader doesn't contain ecdsa.PrivateKey or ecdsa.PublicKey.
func ReadPEM(r io.Reader) ([]interface{}, error) {
    var result []interface{}
    var buf bytes.Buffer
    if _, err := io.Copy(&buf, r); err != nil {
	return nil, errors.Wrapf(err, "read pem")
    }
    rest := buf.Bytes()
    for {
	var block *pem.Block
	block, rest = pem.Decode(rest)
	if block == nil {
	    if result == nil {
		return nil, ErrUnableToLoadKey
	    }
	    return result, nil
	}
	switch block.Type {
	case "EC PRIVATE KEY":
	    priv, err := x509.ParseECPrivateKey(block.Bytes)
	    if err != nil {
		return nil, errors.Wrapf(err, "parse EC private key")
	    }
	    result = append(result, priv)
	case "PUBLIC KEY":
	    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	    if err != nil {
		return nil, errors.Wrapf(err, "parse public key")
	    }
	    if ecdsaPub, ok := pub.(*ecdsa.PublicKey); ok {
		result = append(result, ecdsaPub)
	    }
	}
    }
}

// ReadPrivateKeyPEM reads ecdsa.PrivateKey from io.Reader.
// ReadPrivateKeyPEM returns ErrUnableToLoadKey if io.Reader doesn't contain ecdsa.PrivateKey.
func ReadPrivateKeyPEM(r io.Reader) (*ecdsa.PrivateKey, error) {
    keys, err := ReadPEM(r)
    if err != nil {
	return nil, err
    }
    for _, key := range keys {
	if ecdsaPriv, ok := key.(*ecdsa.PrivateKey); ok {
	    return ecdsaPriv, nil
	}
    }
    return nil, ErrUnableToLoadKey
}

// ReadPublicKeyPEM reads ecdsa.PublicKey from io.Reader.
// ReadPublicKeyPEM returns ErrUnableToLoadKey if io.Reader doesn't contain ecdsa.PublicKey.
func ReadPublicKeyPEM(r io.Reader) (*ecdsa.PublicKey, error) {
    keys, err := ReadPEM(r)
    if err != nil {
	return nil, err
    }
    var priv *ecdsa.PrivateKey
    for _, key := range keys {
	if ecdsaPub, ok := key.(*ecdsa.PublicKey); ok {
	    return ecdsaPub, nil
	}
	if priv == nil {
	    if ecdsaPriv, ok := key.(*ecdsa.PrivateKey); ok {
		priv = ecdsaPriv
	    }
	}
    }
    if priv != nil {
	return &priv.PublicKey, nil
    }
    return nil, ErrUnableToLoadKey
}

func ReadKeyPair(r io.Reader) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
    var priv *ecdsa.PrivateKey
    var pub *ecdsa.PublicKey
    keys, err := ReadPEM(r)
    if err != nil {
	return nil, nil, err
    }
    for _, key := range keys {
	if priv == nil {
	    if ecdsaPriv, ok := key.(*ecdsa.PrivateKey); ok {
		priv = ecdsaPriv
	    }
	}
	if pub == nil {
	    if ecdsaPub, ok := key.(*ecdsa.PublicKey); ok {
		pub = ecdsaPub
	    }
	}
    }
    if priv == nil {
	return nil, nil, ErrUnableToLoadKey
    }
    if pub == nil {
	pub = &priv.PublicKey
    }
    return priv, pub, nil
}

// LoadPrivateKeyPEM reads ecdsa.PrivateKey from a file.
// LoadPrivateKeyPEM returns ErrUnableToLoadKey if the file doesn't contain ecdsa.PrivateKey.
func LoadPrivateKeyPEM(filename string) (*ecdsa.PrivateKey, error) {
    f, err := os.Open(filename)
    if err != nil {
	return nil, err
    }
    defer f.Close()
    return ReadPrivateKeyPEM(f)
}

// LoadPublicKeyPEM reads ecdsa.PublicKey from a file.
// LoadPublicKeyPEM returns ErrUnableToLoadKey if the file doesn't contain ecdsa.PublicKey.
func LoadPublicKeyPEM(filename string) (*ecdsa.PublicKey, error) {
    f, err := os.Open(filename)
    if err != nil {
	return nil, err
    }
    defer f.Close()
    return ReadPublicKeyPEM(f)
}
