package ecc

import (
    "crypto/cipher"
    "crypto/ecdsa"
    "crypto/rand"
    "encoding/asn1"
    "encoding/binary"
    "io"
    "io/ioutil"
    "sync"
    "github.com/pkg/errors"
)

type Encrypt struct {
    PublicKey *ecdsa.PublicKey
    SignKey *ecdsa.PrivateKey
    Cipher interface{}
    Output io.Writer
    ChunkSize uint32
    Random io.Reader
    mutex sync.Mutex
    buffer []byte
    bufpos int
    aead cipher.AEAD
    chunknum uint64
    err error
}

func (e *Encrypt) Write(p []byte) (int, error) {
    e.mutex.Lock()
    defer e.mutex.Unlock()

    if e.err != nil {
	return 0, e.err
    }

    if e.buffer == nil {
	bufferSize := e.ChunkSize
	if bufferSize == 0 {
	    bufferSize = DefaultChunkSize
	}
	e.buffer = make([]byte, bufferSize)
    }

    var n int
    for n < len(p) {
	if e.bufpos == len(e.buffer) {
	    err := e.flush(false)
	    if err != nil {
		return 0, err
	    }
	}
	m := copy(e.buffer[e.bufpos:], p[n:])
	e.bufpos += m
	n += m
    }

    return n, nil
}

func (e *Encrypt) flush(last bool) error {
    if e.err != nil {
	return e.err
    }

    w := e.Output
    // avoid failing if Output is not defined
    if w == nil {
	w = ioutil.Discard
    }

    if e.aead == nil {
	if e.PublicKey == nil {
	    return ErrInvalidKey
	}
	var c *Cipher
	switch e.Cipher.(type) {
	case string:
	    c = LookupCipher(e.Cipher.(string))
	case *Cipher:
	    c = e.Cipher.(*Cipher)
	}
	if c == nil {
	    return ErrInvalidCipher
	}
	kdf := c.KDF
	rr := e.Random
	if rr == nil {
	    rr = rand.Reader
	}
	priv, err := ecdsa.GenerateKey(e.PublicKey.Curve, rr)
	if err != nil {
	    return errors.Wrapf(err, "generate private key")
	}
	key, err := DeriveKey(priv, e.PublicKey, e.PublicKey, c.KeySize, kdf)
	if err != nil {
	    return err
	}
	e.aead, err = c.New(key)
	if err != nil {
	    return err
	}
	if _, err = w.Write(Magic); err != nil {
	    e.err = err
	    return err
	}
	header, err := newHeader(&priv.PublicKey, kdf.OID, c.OID)
	if err != nil {
	    e.err = errors.Wrapf(err, "create header")
	    return e.err
	}
	if e.SignKey != nil {
	    if err = header.Sign(e.SignKey, rr); err != nil {
		e.err = errors.Wrapf(err, "sign")
		return e.err
	    }
	}
	asn1header, err := header.Marshal()
	if err != nil {
	    e.err = errors.Wrapf(err, "marshal header")
	    return e.err
	}
	if _, err = w.Write(asn1header); err != nil {
	    e.err = err
	    return err
	}
    }

    nonce := make([]byte, e.aead.NonceSize())
    binary.LittleEndian.PutUint64(nonce, e.chunknum)
    if last {
	nonce[len(nonce)-1] = 0x01
	e.err = io.ErrClosedPipe
    }
    encrypted := e.aead.Seal(nil, nonce, e.buffer[:e.bufpos], nil)
    chunk, err := asn1.Marshal(encrypted)
    if err != nil {
	e.err = errors.Wrapf(err, "encrypt: flush")
	return e.err
    }
    if _, err := w.Write(chunk); err != nil {
	e.err = err
	return err
    }
    e.bufpos = 0
    e.chunknum++
    return nil
}

func (e *Encrypt) Close() error {
    e.mutex.Lock()
    defer e.mutex.Unlock()
    return e.flush(true)
}
