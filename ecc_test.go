package ecc

import (
    "bytes"
    "crypto/rand"
    "io"
    "strings"
    "testing"
)

func TestKeys(t *testing.T) {
    curve := LookupCurve("P-256")

    priv1, err := GenerateKey(curve, rand.Reader)
    if err != nil {
	t.Fatal(err)
    }
    t.Logf("private key 1: %#v", priv1)

    priv2, err := GenerateKey(curve, rand.Reader)
    if err != nil {
	t.Fatal(err)
    }
    t.Logf("private key 2: %#v", priv2)

    kdf := KDFs["hkdf-sha256"]

    key1, err := DeriveKey(priv2, &priv1.PublicKey, &priv1.PublicKey, 32, kdf)
    if err != nil {
	t.Fatal(err)
    }
    t.Logf("key 1: %x", key1)

    key2, err := DeriveKey(priv1, &priv2.PublicKey, &priv1.PublicKey, 32, kdf)
    if err != nil {
	t.Fatal(err)
    }
    t.Logf("key 2: %x", key2)

    if bytes.Compare(key1, key2) != 0 {
	t.Fatal("derived keys do not match")
    }
}

func TestEncryption(t *testing.T) {
    curve := LookupCurve("P-256")
    t.Logf("curve: %#v", curve)

    priv, err := GenerateKey(curve, rand.Reader)
    if err != nil {
	t.Fatal(err)
    }
    t.Logf("private key: %#v", priv)

    message := "Elliptic Curve Cryptography"

    var encrypted bytes.Buffer
    enc := &Encrypt{
	PublicKey: &priv.PublicKey,
	Cipher: "aes256-gcm",
	Output: &encrypted,
    }
    _, err = io.Copy(enc, strings.NewReader(message))
    if err != nil {
	t.Fatal(err)
    }
    err = enc.Close()
    if err != nil {
	t.Fatal(err)
    }
    t.Logf("encrypted: %x", encrypted.Bytes())

    var decrypted bytes.Buffer
    dec := &Decrypt{
	PrivateKey: priv,
	Input: &encrypted,
    }
    t.Logf("decryptor: %#v", dec)
    _, err = io.Copy(&decrypted, dec)
    if err != nil {
	t.Fatal(err)
    }

    t.Logf("decrypted message: %s", decrypted.String())

    if decrypted.String() != message {
	t.Fatal("encryption error")
    }
}

func benchmarkEncrypt(b *testing.B, cipher string) {
    priv, err := GenerateKey(LookupCurve("P-256"), rand.Reader)
    if err != nil {
	b.Fatal(err)
    }
    enc := &Encrypt{
	PublicKey: &priv.PublicKey,
	Cipher: cipher,
    }
    var buf [1024*1024]byte
    for i := 0; i < b.N; i++ {
	_, err = enc.Write(buf[:])
	if err != nil {
	    b.Fatal(err)
	}
    }
    err = enc.Close()
    if err != nil {
	b.Fatal(err)
    }
}

func BenchmarkEncrypt(b *testing.B) {
    b.Run("aes-128-gcm", func(b *testing.B) { benchmarkEncrypt(b, "aes-128-gcm") })
    b.Run("aes-192-gcm", func(b *testing.B) { benchmarkEncrypt(b, "aes-192-gcm") })
    b.Run("aes-256-gcm", func(b *testing.B) { benchmarkEncrypt(b, "aes-256-gcm") })
    b.Run("chacha20-poly1305", func(b *testing.B) { benchmarkEncrypt(b, "chacha20-poly1305") })
}
