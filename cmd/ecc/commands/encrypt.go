package commands

import (
    "fmt"
    "io"
    "os"
    "github.com/pkg/errors"
    log "github.com/sirupsen/logrus"
    "github.com/spf13/cobra"
    "github.com/thepax/ecc"
    "github.com/thepax/ecc/eccutil"
)

type EncryptOpts struct {
    ListCiphers bool
    Key string
    Sign string
    In string
    Out string
    Rand string
    Cipher string
    Chunk uint32
}

var encryptOpts EncryptOpts

func EncryptCmd() *cobra.Command {
    cmd := &cobra.Command{
	Use: "encrypt",
	Short: "Encrypt file or stream",
	Args: cobra.ExactArgs(0),
	PreRunE: func(cmd *cobra.Command, args []string) error {
	    if !encryptOpts.ListCiphers && encryptOpts.Key == ""{
		return errors.New("public key is not specified")
	    }
	    return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
	    encryptRun(&encryptOpts)
	},
    }
    cmd.Flags().BoolVar(&encryptOpts.ListCiphers, "list-ciphers", false, "list supported ciphers")
    cmd.Flags().StringVar(&encryptOpts.Key, "key", eccutil.GetenvEncryptKey(), "encrypt/public key")
    cmd.Flags().StringVar(&encryptOpts.Sign, "sign", eccutil.GetenvSignKey(), "private key")
    cmd.Flags().StringVarP(&encryptOpts.In, "in", "i", "", "input file (default is stdin)")
    cmd.Flags().StringVarP(&encryptOpts.Out, "out", "o", "", "output file (default is stdout)")
    cmd.Flags().StringVar(&genkeyOpts.Rand, "rand", "", "file to use for random number input")
    cmd.Flags().StringVar(&encryptOpts.Cipher, "cipher", "aes-256-gcm", "encryption cipher")
    cmd.Flags().Uint32Var(&encryptOpts.Chunk, "chunk", ecc.DefaultChunkSize, "encryption chunk size")
    return cmd
}

func encryptRun(opts *EncryptOpts) {
    if opts.ListCiphers {
	for _, c := range ecc.Ciphers {
	    fmt.Printf("%s: %s\n", c.Name, c.Description)
	}
	return
    }

    encryptKey, err := eccutil.GetPublicKey("encrypting", opts.Key)
    if err != nil {
	log.Fatal(err)
    }
    signKey, err := eccutil.GetPrivateKey("signing", opts.Sign)
    if err != nil {
	log.Fatal(err)
    }

    var in *os.File
    if opts.In != "" {
	in, err = os.Open(opts.In)
	if err != nil {
	    log.Fatal("open input: ", err)
	}
	defer in.Close()
    } else {
	in = os.Stdin
    }
    var out *os.File
    if opts.Out != "" {
	out, err = os.OpenFile(opts.Out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
	    log.Fatal("create output: ", err)
	}
	defer func() {
	    if err == nil {
		err = out.Close()
		if err != nil {
		    os.Remove(opts.Out)
		    log.Fatal("close output: ", err)
		}
	    } else {
		out.Close()
		os.Remove(opts.Out)
	    }
	}()
    } else {
	out = os.Stdout
    }
    enc := &ecc.Encrypt{
	PublicKey: encryptKey,
	SignKey: signKey,
	Cipher: opts.Cipher,
	Output: out,
	ChunkSize: opts.Chunk,
    }
    if opts.Rand != "" {
	f, err := os.Open(opts.Rand)
	if err != nil {
	    log.Fatal("open random number input: ", err)
	}
	enc.Random = f
        defer f.Close()
    }
    _, err = io.Copy(enc, in)
    if err != nil {
	log.Fatal("encrypt: ", err)
    }
    err = enc.Close()
    if err != nil {
	log.Fatal("encrypt: ", err)
    }
}
