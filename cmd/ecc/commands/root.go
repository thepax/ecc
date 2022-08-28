package commands

import (
    "github.com/spf13/cobra"
)

func RootCmd(root *cobra.Command) *cobra.Command {
    cmd := &cobra.Command{
	Use:   "ecc",
	Short: "Eliptic Curve Cryptography",
    }
    if root != nil {
	root.AddCommand(cmd)
    }
    cmd.AddCommand(GenkeyCmd())
    cmd.AddCommand(KeyCmd())
    cmd.AddCommand(EncryptCmd())
    cmd.AddCommand(DecryptCmd())
    cmd.AddCommand(EditCmd())
    return cmd
}
