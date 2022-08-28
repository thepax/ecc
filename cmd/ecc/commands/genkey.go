package commands

import (
    "crypto/ecdsa"
    "crypto/rand"
    "fmt"
    "io"
    "os"
    "strings"
    "github.com/pkg/errors"
    "github.com/spf13/cobra"
    log "github.com/sirupsen/logrus"
    "github.com/thepax/ecc"
    "github.com/thepax/ecc/eccutil"
)

type GenkeyOpts struct {
    ListCurves bool
    Curve string
    Cool bool
    FromPassword string
    Pair bool
    Rand string
    SSHAgent string
    Out string
    OutForm string
}

var genkeyOpts GenkeyOpts

func GenkeyCmd() *cobra.Command {
    cmd := &cobra.Command{
	Use: "genkey",
	Short: "Generate new EC key",
	Example: `  ecc genkey --curve P-224
  ecc genkey --curve secp521r1
  ecc genkey --rand /dev/random
  ecc genkey -o my.key
  ecc genkey --password secp521r1:1048576:8:1:SALT`,
	Args: cobra.ExactArgs(0),
	PreRunE: func(cmd *cobra.Command, args []string) error {
	    genkeyOpts.OutForm = strings.ToLower(genkeyOpts.OutForm)
	    switch genkeyOpts.OutForm {
	    case "pem", "short":
	    default:
		return errors.New("invalid output format")
	    }
	    return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
	    genkeyRun(&genkeyOpts)
	},
    }
    cmd.Flags().BoolVar(&genkeyOpts.ListCurves, "list-curves", false, "list supported curves")
    cmd.Flags().StringVar(&genkeyOpts.Curve, "curve", "prime256v1", "curve")
    cmd.Flags().BoolVar(&genkeyOpts.Cool, "cool", false, "generate cool key")
    cmd.Flags().StringVar(&genkeyOpts.FromPassword, "password", "", "generate key from password with scrypt options")
    cmd.Flags().BoolVar(&genkeyOpts.Pair, "pair", false, "generate key pair")
    cmd.Flags().StringVar(&genkeyOpts.Rand, "rand", "", "file to use for random number input")
    cmd.Flags().StringVar(&genkeyOpts.SSHAgent, "ssh-agent", "", "generate key using ssh-agent")
    cmd.Flags().StringVarP(&genkeyOpts.Out, "out", "o", "", "output file (default is stdout)")
    cmd.Flags().StringVar(&genkeyOpts.OutForm, "outform", "pem", "output format - pem, short")
    return cmd
}

func genkeyRun(opts *GenkeyOpts) {
    var err error

    if opts.ListCurves {
	for _, curve := range ecc.Curves {
	    aliases := strings.Join(curve.Aliases, ", ")
	    if aliases == "" {
		fmt.Printf("%s: %s\n", curve.Name, curve.Description)
	    } else {
		fmt.Printf("%s (%s): %s\n", curve.Name, aliases, curve.Description)
	    }
	}
	return
    }

    curve := ecc.LookupCurve(opts.Curve)
    if curve == nil {
	log.Fatalf("curve not found: %s", opts.Curve)
    }

    var rnd io.Reader
    if opts.Rand != "" {
	f, err := os.Open(opts.Rand)
	if err != nil {
	    log.Fatal("open random number input: ", err)
	}
	rnd = f
	defer f.Close()
    } else {
	rnd = rand.Reader
    }

    var scryptOpts *ecc.SCryptOpts
    if opts.FromPassword != "" {
	scryptOpts, err = eccutil.ParseSCryptOpts(opts.FromPassword)
	if err != nil {
	    log.Fatalf("scrypt options: \"%s\": %v", opts.FromPassword, err)
	}
    }

    var priv1, priv2 *ecdsa.PrivateKey
    if scryptOpts != nil {
	var password []byte
	if opts.Pair {
	    password, err = eccutil.NewPassword("Side A Password: ")
	} else {
	    password, err = eccutil.NewPassword("Password: ")
	}
	if err == nil {
	    priv1, err = ecc.GenerateKeyFromPassword(password, scryptOpts)
	}
    } else {
	if opts.SSHAgent != "" {
	    priv1, err = eccutil.SSHAgentKey(opts.SSHAgent)
	} else {
	    if opts.Cool {
		priv1, err = ecc.GenerateCoolKey(curve, rnd)
	    } else {
		priv1, err = ecc.GenerateKey(curve, rnd)
	    }
	}
    }
    if err != nil {
	log.Fatal("generate key: ", err)
    }
    if opts.Pair {
	if scryptOpts != nil {
	    var password []byte
	    password, err = eccutil.NewPassword("Side B Password: ")
	    if err == nil {
		priv2, err = ecc.GenerateKeyFromPassword(password, scryptOpts)
	    }
	} else {
	    if opts.Cool {
		priv2, err = ecc.GenerateCoolKey(curve, rnd)
	    } else {
		priv2, err = ecc.GenerateKey(curve, rnd)
	    }
	}
	if err != nil {
	    log.Fatal("generate key: ", err)
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
	if out, err = os.OpenFile(opts.Out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600); err != nil {
	    return
	}
	defer func() {
	    if err == nil {
		err = out.Close()
	    }
	}()
    }
    if priv2 == nil {
	switch opts.OutForm {
	case "pem":
	    err = ecc.WritePEM(priv1, out)
	case "short":
	    var shortKey []byte
	    if shortKey, err = ecc.MarshalShortKey(priv1); err != nil {
		return
	    }
	    if _, err = out.Write(shortKey); err != nil {
		return
	    }
	    _, err = out.Write([]byte("\n"))
	}
    } else {
	if _, err = fmt.Fprintf(out, "Side A:\n"); err != nil {
	    return
	}
	switch opts.OutForm {
	case "pem":
	    if err = ecc.WritePEM(priv1, out); err != nil {
		return
	    }
	    if err = ecc.WritePEM(&priv2.PublicKey, out); err != nil {
		return
	    }
	case "short":
	    var shortKey []byte
	    if shortKey, err = ecc.MarshalShortKey(priv1); err != nil {
		return
	    }
	    if _, err = out.Write([]byte("Decrypt/sign key: ")); err != nil {
		return
	    }
	    if _, err = out.Write(shortKey); err != nil {
		return
	    }
	    if shortKey, err = ecc.MarshalShortKey(&priv2.PublicKey); err != nil {
		return
	    }
	    if _, err = out.Write([]byte("\nEncrypt/verify key: ")); err != nil {
		return
	    }
	    if _, err = out.Write(shortKey); err != nil {
		return
	    }
	    if _, err = out.Write([]byte("\n")); err != nil {
		return
	    }
	}
	if _, err = out.Write([]byte("\nSide B:\n")); err != nil {
	    return
	}
	switch opts.OutForm {
	case "pem":
	    if err = ecc.WritePEM(priv2, out); err != nil {
		return
	    }
	    if err = ecc.WritePEM(&priv1.PublicKey, out); err != nil {
		return
	    }
	case "short":
	    var shortKey []byte
	    if shortKey, err = ecc.MarshalShortKey(priv2); err != nil {
		return
	    }
	    if _, err = out.Write([]byte("Decrypt/sign key: ")); err != nil {
		return
	    }
	    if _, err = out.Write(shortKey); err != nil {
		return
	    }
	    if shortKey, err = ecc.MarshalShortKey(&priv1.PublicKey); err != nil {
		return
	    }
	    if _, err = out.Write([]byte("\nEncrypt/verify key: ")); err != nil {
		return
	    }
	    if _, err = out.Write(shortKey); err != nil {
		return
	    }
	    if _, err = out.Write([]byte("\n")); err != nil {
		return
	    }
	}
    }
}
