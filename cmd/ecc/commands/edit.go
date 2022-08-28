package commands

import (
    "crypto/rand"
    "io"
    "os"
    "os/exec"
    "github.com/pkg/errors"
    log "github.com/sirupsen/logrus"
    "github.com/spf13/cobra"
    "github.com/thepax/ecc"
    "github.com/thepax/ecc/eccutil"
)

type EditOpts struct {
    Cipher string
    Key string
    Rand string
}

var editOpts EditOpts

func EditCmd() *cobra.Command {
    cmd := &cobra.Command{
	Use: "edit [flags] filename.ecc",
	Short: "Edit an encrypted file",
	Args: cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
	    if editOpts.Key == "" {
		return errors.New("private key is not specified")
	    }
	    return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
	    editRun(&editOpts, args[0])
	},
    }
    cmd.Flags().StringVar(&editOpts.Cipher, "cipher", "aes-256-gcm", "encryption cipher")
    cmd.Flags().StringVar(&editOpts.Key, "key", eccutil.GetenvPrivateKey(), "private key")
    cmd.Flags().StringVar(&editOpts.Rand, "rand", "", "file to use for random number input")
    return cmd
}

func editRun(opts *EditOpts, filename string) {
    err := editDoRun(opts, filename)
    if err != nil {
	log.Fatal(err)
    }
}

func editDoRun(opts *EditOpts, filename string) error {
    privateKey, err := eccutil.GetPrivateKey("decrypting", opts.Key)
    if err != nil {
	return err
    }

    randReader := rand.Reader
    if opts.Rand != "" {
	f, err := os.Open(opts.Rand)
	if err != nil {
	    log.Fatal("open random number input: ", err)
	}
	randReader = f
	defer f.Close()
    }

    var f *os.File
    if _, err := os.Stat(filename); !os.IsNotExist(err) {
	f, err = os.OpenFile(filename, os.O_RDWR, 0600)
	if err != nil {
	    return err
	}
	defer f.Close()
    }

    tmpf, err := os.CreateTemp("", "ecc*.txt")
    if err != nil {
	return err
    }
    tempfile := tmpf.Name()
    defer func() {
	if fi, err := os.Stat(tempfile); err == nil && fi.Size() > 0 {
	    tmpf, err := os.OpenFile(tempfile, os.O_RDWR, 0600)
	    if err == nil {
		io.CopyN(tmpf, randReader, fi.Size())
		tmpf.Close()
	    }
	}
	os.Remove(tempfile)
    }()

    if f != nil {
	dec := &ecc.Decrypt{
	    PrivateKey: privateKey,
	    VerifyKey: &privateKey.PublicKey,
	    Input: f,
	}
	_, err = io.Copy(tmpf, dec)
	if err != nil {
	    tmpf.Close()
	    return errors.Wrap(err, "decrypt")
	}
    }
    if err = tmpf.Close(); err != nil {
	return errors.Wrap(err, "decrypt")
    }

    editor := os.Getenv("EDITOR")
    if editor == "" {
	editor = "vi"
    }
    cmd := exec.Command(editor, tempfile)
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil {
	return errors.Wrap(err, "run editor")
    }

    if f == nil {
	f, err = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
	    return err
	}
	defer f.Close()
    }
    if _, err = f.Seek(0, os.SEEK_SET); err != nil {
	return err
    }

    tmpf, err = os.Open(tempfile)
    if err != nil {
	return errors.Wrap(err, "encrypt")
    }
    defer tmpf.Close()

    enc := &ecc.Encrypt{
	PublicKey: &privateKey.PublicKey,
	SignKey: privateKey,
	Cipher: opts.Cipher,
	Output: f,
	Random: randReader,
    }
    _, err = io.Copy(enc, tmpf)
    if err != nil {
	return errors.Wrap(err, "encrypt")
    }
    if err = enc.Close(); err != nil {
	return errors.Wrap(err, "encrypt")
    }
    pos, err := f.Seek(0, os.SEEK_CUR)
    if err != nil {
	return errors.Wrap(err, "encrypt")
    }
    if err = f.Truncate(pos); err != nil {
	return errors.Wrap(err, "encrypt")
    }
    if err = f.Sync(); err != nil {
	return errors.Wrap(err, "encrypt")
    }
    return nil
}
