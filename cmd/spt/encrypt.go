package spt

import (
	"encoding/base64"
	"gitea.suyono.dev/suyono/simple-privacy-tool/privacy"
	"io"
)

type encryptApp struct {
	cApp
	wc *privacy.WriteCloser
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
	var dst io.WriteCloser

	if f.IsBase64() {
		dst = base64.NewEncoder(base64.StdEncoding, e.dstFile)
	} else {
		dst = e.dstFile
	}

	if f.IncludeHint() {
		if err = WriteHint(f.KeyGen(), dst); err != nil {
			return
		}
	}

	e.wc = privacy.NewPrivacyWriteCloserWithKeyGen(dst, f.CipherMethod(), f.KeyGen())
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
