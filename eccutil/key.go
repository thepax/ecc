package eccutil

import (
    "crypto/ecdsa"
    "fmt"
    "strconv"
    "strings"
    "github.com/pkg/errors"
    "github.com/thepax/ecc"
)

func ParseSCryptOpts(opts string) (*ecc.SCryptOpts, error) {
    var err error

    so := ecc.NewDefaultSCryptOpts()

    o := strings.Split(opts, ":")
    if len(o) > 0 && o[0] != "" {
	so.Curve = ecc.LookupCurve(o[0])
	if so.Curve == nil {
	    return nil, ecc.ErrUnsupportedCurve
	}
    }
    if len(o) > 1 && o[1] != "" {
	so.N, err = strconv.Atoi(o[1])
	if err != nil {
	    return nil, errors.Wrapf(err, "N")
	}
    }
    if len(o) > 2 && o[2] != "" {
	so.R, err = strconv.Atoi(o[2])
	if err != nil {
	    return nil, errors.Wrapf(err, "r")
	}
    }
    if len(o) > 3 && o[3] != "" {
	so.P, err = strconv.Atoi(o[3])
	if err != nil {
	    return nil, errors.Wrapf(err, "p")
	}
    }
    if len(o) > 4 && o[4] != "" {
	so.Salt = []byte(o[4])
    }
    return so, nil
}

var passwordKeys map[string]*ecdsa.PrivateKey
var sshAgentKeys map[string]*ecdsa.PrivateKey

func GetPrivateKey(purpose, key string) (*ecdsa.PrivateKey, error) {
    var privateKey *ecdsa.PrivateKey
    var err error

    if key == "" {
	return nil, errors.Errorf("no %s defined", purpose)
    }

    if strings.HasPrefix(key, "ecc") {
	privateKey, err = ecc.UnmarshalShortPrivateKey([]byte(key))
	if err != nil {
	    return nil, errors.Wrapf(err, "parse %s key", purpose)
	}
	return privateKey, nil
    }
    if strings.HasPrefix(key, "password:") {
	if passwordKeys == nil {
	    passwordKeys = make(map[string]*ecdsa.PrivateKey)
	}
	if passwordKeys[key] != nil {
	    return passwordKeys[key], nil
	}
	scryptOpts, err := ParseSCryptOpts(key[9:])
	if err != nil {
	    return nil, errors.Wrap(err, "parse scrypt options")
	}
	var password []byte
	if purpose == "decrypting" {
	    password, err = GetPassword("Password: ")
	} else {
	    password, err = NewPassword(fmt.Sprintf("%s Password: ", strings.Title(purpose)))
	}
	if err != nil {
	    return nil, errors.Wrapf(err, "%s password", purpose)
	}
	privateKey, err = ecc.GenerateKeyFromPassword(password, scryptOpts)
	if err != nil {
	    return nil, errors.Wrapf(err, "derive %s key", purpose)
	}
	passwordKeys[key] = privateKey
	return privateKey, nil
    }
    if strings.HasPrefix(key, "ssh-agent:") {
	if sshAgentKeys == nil {
	    sshAgentKeys = make(map[string]*ecdsa.PrivateKey)
	}
	if sshAgentKeys[key] != nil {
	    return sshAgentKeys[key], nil
	}
	privateKey, err = SSHAgentKey(key[10:])
	if err != nil {
	    return nil, err
	}
	sshAgentKeys[key] = privateKey
	return privateKey, nil
    }
    privateKey, err = ecc.LoadPrivateKeyPEM(key)
    if err != nil {
	return nil, errors.Wrapf(err, "load %s key", purpose)
    }
    return privateKey, nil
}

func GetPublicKey(purpose, key string) (*ecdsa.PublicKey, error) {
    var publicKey *ecdsa.PublicKey
    var err error

    if key == "" {
	return nil, errors.Errorf("no %s defined", purpose)
    }

    if strings.HasPrefix(key, "ecc") {
	publicKey, err = ecc.UnmarshalShortPublicKey([]byte(key))
	if err != nil {
	    return nil, errors.Wrapf(err, "parse %s key", purpose)
	}
	return publicKey, nil
    }
    if strings.HasPrefix(key, "password:") {
	if passwordKeys == nil {
	    passwordKeys = make(map[string]*ecdsa.PrivateKey)
	}
	if passwordKeys[key] != nil {
	    return &passwordKeys[key].PublicKey, nil
	}
	scryptOpts, err := ParseSCryptOpts(key[9:])
	if err != nil {
	    return nil, errors.Wrap(err, "parse scrypt options")
	}
	var password []byte
	if purpose == "encrypting" {
	    password, err = NewPassword("Password: ")
	} else {
	    password, err = GetPassword(fmt.Sprintf("%s Password: ", strings.Title(purpose)))
	}
	if err != nil {
	    return nil, errors.Wrapf(err, "%s password", purpose)
	}
	privateKey, err := ecc.GenerateKeyFromPassword(password, scryptOpts)
	if err != nil {
	    return nil, errors.Wrapf(err, "derive %s key", purpose)
	}
	passwordKeys[key] = privateKey
	return &privateKey.PublicKey, nil
    }
    if strings.HasPrefix(key, "ssh-agent:") {
	if sshAgentKeys == nil {
	    sshAgentKeys = make(map[string]*ecdsa.PrivateKey)
	}
	if sshAgentKeys[key] != nil {
	    return &sshAgentKeys[key].PublicKey, nil
	}
	privateKey, err := SSHAgentKey(key[10:])
	if err != nil {
	    return nil, err
	}
	sshAgentKeys[key] = privateKey
	return &privateKey.PublicKey, nil
    }
    publicKey, err = ecc.LoadPublicKeyPEM(key)
    if err != nil {
	return nil, errors.Wrapf(err, "load %s key", purpose)
    }
    return publicKey, nil
}
