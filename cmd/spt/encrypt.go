package spt

import (
	"gitea.suyono.dev/suyono/simple-privacy-tool/privacy"
	"io"
)

type encryptApp struct {
	cApp
	wc *privacy.WriteCloser
}

func newEncryptApp(a *cApp) *encryptApp {
	return &encryptApp{
		cApp: *a,
	}
}

func (e *encryptApp) GetPassphrase() (err error) {
	var (
		passphrase string
		verify     string
	)

	if passphrase, err = e.term.ReadPassword("input passphrase: "); err != nil {
		return
	}

	if verify, err = e.term.ReadPassword("verify - input passphrase: "); err != nil {
		return
	}

	if passphrase != verify {
		return ErrPassphraseMismatch
	}

	e.passphrase = passphrase

	return nil
}

func (e *encryptApp) ProcessFiles() (err error) {
	e.wc = privacy.NewPrivacyWriteCloser(e.dstFile, privacy.DefaultCipherMethod) //TODO: need to handle when custom keygen accepted
	if err = e.wc.NewSalt(); err != nil {
		return
	}

	if err = e.wc.GenerateKey(e.passphrase); err != nil {
		return
	}

	if _, err = io.Copy(e.wc, e.srcFile); err != nil {
		return
	}

	if err = e.wc.Close(); err != nil {
		return
	}

	if err = e.srcFile.Close(); err != nil {
		return
	}

	return
}
