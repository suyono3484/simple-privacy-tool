package spt

import (
	"errors"
	"os"

	tw "gitea.suyono.dev/suyono/terminal_wrapper"
	"github.com/spf13/cobra"
	"log"
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
		Use:   "simple-privacy-tool",
		Short: "a simple tool to encrypt and decrypt file",
	}

	hintCmd = &cobra.Command{
		Use:   "hint file",
		Args:  cobra.ExactArgs(1),
		RunE:  CmdReadHint,
		Short: "extract and print hint from encrypted file",
	}

	encryptCmd = &cobra.Command{
		Use:  "encrypt srcFile dstFile",
		Args: validatePositionalArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := processFlags(); err != nil {
				return err
			}
			return encrypt(cmd, args)
		},
		Short: "encrypt srcFile, output to dstFile",
	}

	decryptCmd = &cobra.Command{
		Use: "decrypt srcFile dstFile",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := processFlags(); err != nil {
				return err
			}
			return decrypt(cmd, args)
		},
		Args:  validatePositionalArgs,
		Short: "decrypt srcFile, output to dstFile",
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	initFlags()
	rootCmd.AddCommand(encryptCmd, decryptCmd, hintCmd)
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
	log.SetOutput(terminal)
	defer func() {
		existingErr := err
		if err = terminal.Restore(); err == nil && existingErr != nil {
			err = existingErr
		}
		log.SetOutput(os.Stderr)
	}()

	app = &cApp{
		term: terminal,
	}

	if err = app.ProcessArgs(args); err != nil {
		return
	}

	eApp = &encryptApp{
		cApp: *app,
	}

	if err = eApp.GetPassphrase(); err != nil {
		return
	}

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
	log.SetOutput(terminal)
	defer func() {
		existingErr := err
		if err = terminal.Restore(); err == nil && existingErr != nil {
			err = existingErr
		}
		log.SetOutput(os.Stderr)
	}()

	app = &cApp{
		term: terminal,
	}

	if err = app.ProcessArgs(args); err != nil {
		return
	}

	dApp = &decryptApp{
		cApp: *app,
	}

	if err = dApp.GetPassphrase(); err != nil {
		return
	}

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
