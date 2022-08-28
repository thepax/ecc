package commands

import (
    "bytes"
    "crypto/ecdsa"
    "io"
    "os"
    "strings"
    "github.com/pkg/errors"
    "github.com/spf13/cobra"
    log "github.com/sirupsen/logrus"
    "github.com/thepax/ecc"
)

type KeyOpts struct {
    In string
    Out string
    NoOut bool
    PubOut bool
    InForm string
    OutForm string
}

var keyOpts KeyOpts

func KeyCmd() *cobra.Command {
    cmd := &cobra.Command{
	Use: "key",
	Short: "EC key operations",
	Args: cobra.ExactArgs(0),
	PreRunE: func(cmd *cobra.Command, args []string) error {
	    keyOpts.InForm = strings.ToLower(keyOpts.InForm)
	    switch keyOpts.InForm {
	    case "pem", "short":
	    default:
		return errors.New("invalid input format")
	    }
	    keyOpts.OutForm = strings.ToLower(keyOpts.OutForm)
	    switch keyOpts.OutForm {
	    case "pem", "short":
	    default:
		return errors.New("invalid output format")
	    }
	    return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
	    keyRun(&keyOpts)
	},
    }
    cmd.Flags().StringVarP(&keyOpts.In, "in", "i", "", "input file (default is stdin)")
    cmd.Flags().StringVarP(&keyOpts.Out, "out", "o", "", "output file (default is stdout)")
    cmd.Flags().BoolVar(&keyOpts.NoOut, "noout", false, "don't print key out")
    cmd.Flags().BoolVar(&keyOpts.PubOut, "pubout", false, "print public key")
    cmd.Flags().StringVar(&keyOpts.InForm, "inform", "pem", "input format - pem, short")
    cmd.Flags().StringVar(&keyOpts.OutForm, "outform", "pem", "output format - pem, short")
    return cmd
}

func loadKeys(filename string, inform string) []interface{} {
    var err error
    var f *os.File
    var keys []interface{}

    if strings.HasPrefix(filename, "ecc") {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
	    keys, err := ecc.UnmarshalShortKeys([]byte(filename))
	    if err != nil {
		log.Fatalf("parse short keys: %v", err)
	    }
	    return keys
	}
    }

    if filename == "" {
	f = os.Stdin
    } else {
	f, err = os.Open(filename)
	if err != nil {
	    log.Fatal(err)
	}
	defer f.Close()
    }
    switch inform {
    case "pem":
	keys, err = ecc.ReadPEM(f)
    case "short":
	var buf bytes.Buffer
	_, err = io.Copy(&buf, f)
	if err == nil {
	    keys, err = ecc.UnmarshalShortKeys(buf.Bytes())
	}
    }
    if err != nil {
	log.Fatal("read key: ", err)
    }
    return keys
}

func keyRun(opts *KeyOpts) {
    var err error
    keys := loadKeys(opts.In, opts.InForm)
    if opts.NoOut || len(keys) == 0 {
	return
    }
    var outKeys []interface{}
    for _, key := range keys {
	if priv, ok := key.(*ecdsa.PrivateKey); ok {
	    if opts.PubOut {
		outKeys = append(outKeys, &priv.PublicKey)
	    } else {
		outKeys = append(outKeys, priv)
	    }
	} else if pub, ok := key.(*ecdsa.PublicKey); ok {
	    outKeys = append(outKeys, pub)
	}
    }
    var perm os.FileMode = 0666
    for _, key := range keys {
	if _, ok := key.(*ecdsa.PrivateKey); ok {
	    perm = 0600
	}
    }

    var out *os.File
    defer func() {
	if err != nil {
	    log.Fatalf("could not create file: %v", err)
	}
    }()
    if opts.Out == "" {
	out = os.Stdout
    } else {
	if out, err = os.OpenFile(opts.Out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm); err != nil {
	    return
	}
	defer func() {
	    if err == nil {
		err = out.Close()
	    }
	}()
    }
    for _, key := range outKeys {
	switch keyOpts.OutForm {
	case "pem":
	    err = ecc.WritePEM(key, out)
	case "short":
	    var shortKey []byte
	    shortKey, err = ecc.MarshalShortKey(key)
	    if err != nil {
		return
	    }
	    _, err = out.Write(shortKey)
	    if err != nil {
		return
	    }
	    _, err = out.Write([]byte("\n"))
	}
	if err != nil {
	    return
	}
    }
}
