package eccutil

import (
    "crypto/ecdsa"
    "crypto/sha256"
    "encoding/base64"
    "net"
    "os"
    "strings"
    "github.com/pkg/errors"
    "golang.org/x/crypto/ssh/agent"
    "github.com/thepax/ecc"
)

func SSHAgentKey(opts string) (*ecdsa.PrivateKey, error) {
    o := strings.Split(opts, ":")
    if len(o) != 3 {
	return nil, errors.Errorf("invalid ssh agent options: %s", opts)
    }
    if o[0] == "" {
	o[0] = "secp521r1"
    }
    curve := ecc.LookupCurve(o[0])
    if curve == nil {
	return nil,errors.Wrapf(ecc.ErrUnsupportedCurve, "ssh agent options")
    }
    pubKey := o[1]
    var salt []byte
    if o[2] != "" {
	salt = []byte(o[2])
    } else {
	salt = []byte(o[1])
    }

    sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
    if sshAuthSock == "" {
	return nil, errors.New("no ssh agent found")
    }
    conn, err := net.Dial("unix", sshAuthSock)
    if err != nil {
	return nil, errors.Wrapf(err, "connect to ssh agent")
    }
    defer conn.Close()
    sshAgent := agent.NewClient(conn)
    signers, err := sshAgent.Signers()
    if err != nil {
	return nil, errors.Wrapf(err, "get ssh agent keys")
    }
    for _, signer := range signers {
	hash := sha256.New()
	hash.Write(signer.PublicKey().Marshal())
	if base64.RawStdEncoding.EncodeToString(hash.Sum(nil)) == pubKey {
	    signature, err := signer.Sign(nil, salt)
	    if err != nil {
		return nil, errors.Wrap(err, "ssh agent sign")
	    }
	    return ecc.GenerateKeyFromData(curve, signature.Blob, salt)
	}
    }
    return nil, errors.New("ssh agent key not found")
}
