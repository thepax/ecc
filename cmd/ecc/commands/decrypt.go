package commands

import (
    "io"
    "os"
    "github.com/pkg/errors"
    log "github.com/sirupsen/logrus"
    "github.com/spf13/cobra"
    "github.com/thepax/ecc"
    "github.com/thepax/ecc/eccutil"
)

type DecryptOpts struct {
    Key string
    Verify string
    In string
    Out string
}

var decryptOpts DecryptOpts

func DecryptCmd() *cobra.Command {
    cmd := &cobra.Command{
	Use: "decrypt",
	Short: "Decrypt file or stream",
	Args: cobra.ExactArgs(0),
	PreRunE: func(cmd *cobra.Command, args []string) error {
	    if decryptOpts.Key == "" {
		return errors.New("private key is not specified")
	    }
	    return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
	    decryptRun(&decryptOpts)
	},
    }
    cmd.Flags().StringVar(&decryptOpts.Key, "key", eccutil.GetenvDecryptKey(), "decrypt/private key")
    cmd.Flags().StringVar(&decryptOpts.Verify, "verify", eccutil.GetenvVerifyKey(), "public key")
    cmd.Flags().StringVarP(&decryptOpts.In, "in", "i", "", "input file (default is stdin)")
    cmd.Flags().StringVarP(&decryptOpts.Out, "out", "o", "", "output file (default is stdout)")
    return cmd
}

func decryptRun(opts *DecryptOpts) {
    var err error

    decryptKey, err := eccutil.GetPrivateKey("decrypting", opts.Key)
    if err != nil {
	log.Fatal(err)
    }
    verifyKey, err := eccutil.GetPublicKey("verifying", opts.Verify)
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
    dec := &ecc.Decrypt{
	PrivateKey: decryptKey,
	VerifyKey: verifyKey,
	Input: in,
    }
    _, err = io.Copy(out, dec)
    if err != nil {
	log.Fatal("decrypt: ", err)
    }
}
