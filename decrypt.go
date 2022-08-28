package ecc

import (
    "crypto/cipher"
    "crypto/ecdsa"
    "encoding/asn1"
    "encoding/binary"
    "io"
    "sync"
    "github.com/pkg/errors"
)

type Decrypt struct {
    PrivateKey *ecdsa.PrivateKey
    VerifyKey *ecdsa.PublicKey
    Input io.Reader
    mutex sync.Mutex
    version int
    aead cipher.AEAD
    buffer []byte
    bufpos int
    chunknum uint64
    err error
}

func readASN1(r io.Reader) (packet []byte, err error) {
    defer func() {
	if err == io.EOF {
	    err = io.ErrUnexpectedEOF
	} else {
	    err = errors.Wrapf(err, "read asn1")
	}
    }()
    var buf [10]byte
    hl := uint64(2)
    if _, err = io.ReadFull(r, buf[:hl]); err != nil {
	return
    }
    if (buf[0] & 0x1f) == 0x1f {
	return nil, errors.New("tag too big")
    }
    var l uint64
    if (buf[1] & 0x80) == 0 {
	l = uint64(buf[1])
    } else {
	if buf[1] == 0xff || buf[1] == 0x80 {
	    return nil, errors.New("invalid length")
	}
	ll := uint64(buf[1] & 0x7f)
	if ll > 8 {
	    return nil, errors.New("too long")
	}
	hl += ll
	if _, err = io.ReadFull(r, buf[2:hl]); err != nil {
	    return
	}
	for i := 2; i < int(hl); i++ {
	    l = (l << 8) + uint64(buf[i])
	}
    }
    p := make([]byte, hl + l)
    copy(p, buf[:hl])
    if _, err = io.ReadFull(r, p[hl:]); err != nil {
	return
    }
    return p, nil
}

func readHeader(r io.Reader) (version int, header *eccHeader, err error) {
    defer func() {
	err = errors.Wrapf(err, "read header")
    }()
    var hbuf [6]byte
    if _, err = io.ReadFull(r, hbuf[:]); err != nil {
	if err == io.ErrUnexpectedEOF {
	    err = ErrBadMagic
	}
	return
    }
    if version, err = MagicVersion(hbuf[:]); err != nil {
	return
    }
    var buf []byte
    if buf, err = readASN1(r); err != nil {
	return
    }
    header, err = unmarshalHeader(buf)
    return
}

func (d *Decrypt) Read(p []byte) (n int, err error) {
    defer func() {
	if err != nil && d.err == nil {
	    d.err = err
	}
	if err != io.EOF {
	    err = errors.Wrapf(err, "ecc read")
	}
    }()

    d.mutex.Lock()
    defer d.mutex.Unlock()

    if (d.err == nil || d.err == io.EOF) && d.bufpos < len(d.buffer) {
	m := copy(p, d.buffer[d.bufpos:])
	n += m
	d.bufpos += m
	if d.err == io.EOF {
	    return n, nil
	}
    }

    if d.err != nil {
	return 0, d.err
    }

    if d.Input == nil {
	return 0, io.EOF
    }

    if d.aead == nil {
	var header *eccHeader
	d.version, header, err = readHeader(d.Input)
	if err != nil {
	    return 0, err
	}
	if d.VerifyKey != nil {
	    if err = header.Verify(d.VerifyKey); err != nil {
		return 0, err
	    }
	}
	pub, err := header.PublicKey()
	if err != nil {
	    return 0, err
	}
	if pub.Curve.Params().Name != d.PrivateKey.Curve.Params().Name {
	    return 0, ErrInvalidKey
	}
	if !d.PrivateKey.Curve.IsOnCurve(pub.X, pub.Y) {
	    return 0, ErrInvalidKey
	}
	kdf, err := header.KDF()
	if err != nil {
	    return 0, err
	}
	c, err := header.Cipher()
	if err != nil {
	    return 0, err
	}
	key, err := DeriveKey(d.PrivateKey, pub, &d.PrivateKey.PublicKey, c.KeySize, kdf)
	if err != nil {
	    return 0, err
	}
	d.aead, err = c.New(key)
	if err != nil {
	    return 0, err
	}
    }

    for n < len(p) {
	if d.bufpos >= len(d.buffer) {
	    if d.err == io.EOF {
		return
	    }
	    var buf []byte
	    if buf, err = readASN1(d.Input); err != nil {
		return
	    }
	    var chunk []byte
	    if _, err = asn1.Unmarshal(buf, &chunk); err != nil {
		return n, ErrBadEncoding
	    }
	    nonce := make([]byte, d.aead.NonceSize())
	    binary.LittleEndian.PutUint64(nonce, d.chunknum)
	    d.chunknum++
	    d.bufpos = 0
	    if d.buffer, err = d.aead.Open(nil, nonce, chunk, nil); err != nil {
		nonce[len(nonce)-1] = 0x01
		if d.buffer, err = d.aead.Open(nil, nonce, chunk, nil); err != nil {
		    return
		}
		d.err = io.EOF
	    }
	    if len(d.buffer) == 0 {
		d.err = io.EOF
		if n > 0 {
		    return
		}
		return 0, io.EOF
	    }
	}
	m := copy(p[n:], d.buffer[d.bufpos:])
	n += m
	d.bufpos += m
    }
    return
}
