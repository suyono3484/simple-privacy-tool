package spt

import (
	"errors"
	tw "gitea.suyono.dev/suyono/terminal_wrapper"
	"github.com/spf13/cobra"
	"os"
)

type cApp struct {
	term       *tw.Terminal
	srcPath    string
	dstPath    string
	srcFile    *os.File
	dstFile    *os.File
	passphrase string
}

var (
	//ErrFatalError         = errors.New("fatal error occurred")
	ErrPassphraseMismatch = errors.New("mismatch passphrase")

	rootCmd = &cobra.Command{
		Use:   "spt",
		Short: "a simple tool to encrypt and decrypt file",
	}

	encryptCmd = &cobra.Command{
		Use:  "encrypt",
		Args: validatePositionalArgs,
		RunE: encrypt,
	}

	decryptCmd = &cobra.Command{
		Use:  "decrypt",
		RunE: decrypt,
		Args: validatePositionalArgs,
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(encryptCmd, decryptCmd)
}

func validatePositionalArgs(cmd *cobra.Command, args []string) error {
	if len(args) != 0 && len(args) != 2 {
		//TODO: improve the error message
		return errors.New("invalid arguments")
	}

	return nil
}

func encrypt(cmd *cobra.Command, args []string) (err error) {
	var (
		terminal *tw.Terminal
		app      *cApp
		eApp     *encryptApp
	)

	if terminal, err = tw.MakeTerminal(os.Stderr); err != nil {
		return
	}
	defer func() {
		existingErr := err
		if err = terminal.Restore(); err == nil && existingErr != nil {
			err = existingErr
		}
	}()

	app = &cApp{
		term: terminal,
	}

	if err = app.ProcessArgs(args); err != nil {
		return
	}

	eApp = newEncryptApp(app)

	if err = eApp.GetPassphrase(); err != nil {
		return
	}

	//TODO: process additional flags

	if err = eApp.ProcessFiles(); err != nil {
		return
	}

	return nil
}

func decrypt(cmd *cobra.Command, args []string) (err error) {
	var (
		terminal *tw.Terminal
		app      *cApp
		dApp     *decryptApp
	)

	if terminal, err = tw.MakeTerminal(os.Stderr); err != nil {
		return
	}
	defer func() {
		existingErr := err
		if err = terminal.Restore(); err == nil && existingErr != nil {
			err = existingErr
		}
	}()

	app = &cApp{
		term: terminal,
	}

	if err = app.ProcessArgs(args); err != nil {
		return
	}

	dApp = newDecryptApp(app)

	if err = dApp.GetPassphrase(); err != nil {
		return
	}

	//TODO: process additional flags

	if err = dApp.ProcessFiles(); err != nil {
		return
	}

	return nil
}

func (a *cApp) ProcessArgs(args []string) (err error) {
	if len(args) == 0 {
		a.srcFile = os.Stdin
		a.dstFile = os.Stdout
	} else {
		a.srcPath = args[0]
		a.dstPath = args[1]
		if a.srcPath == "-" {
			a.srcFile = os.Stdin
		} else {
			if a.srcFile, err = os.Open(a.srcPath); err != nil {
				return
			}
		}

		if a.dstPath == "-" {
			a.dstFile = os.Stdout
		} else {
			if a.dstFile, err = os.OpenFile(a.dstPath, os.O_CREATE|os.O_WRONLY, 0640); err != nil { //TODO: allow user to define the destination file permission
				return
			}
		}
	}
	return
}
