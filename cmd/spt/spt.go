package spt

import (
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "spt",
		Short: "a simple tool to encrypt and decrypt file",
	}

	encryptCmd = &cobra.Command{
		Use:  "encrypt",
		RunE: encrypt,
	}

	decryptCmd = &cobra.Command{
		Use:  "decrypt",
		RunE: decrypt,
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(encryptCmd, decryptCmd)
}

func encrypt(cmd *cobra.Command, args []string) error {
	//TODO: implementation

	//// this is the sample of reading password
	//fmt.Print("input passphrase: ")
	//passwd, err := privacy.ReadPassword()
	//if err != nil {
	//	return err
	//}
	//fmt.Println()
	//
	//fmt.Printf("password: %s\n", passwd)
	//// end of sample

	return nil
}

func decrypt(cmd *cobra.Command, args []string) error {
	//TODO: implementation
	return nil
}
