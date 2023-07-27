package spt

import (
	"encoding/base64"
	"fmt"
	"gitea.suyono.dev/suyono/simple-privacy-tool/privacy"
	"io"
)

type decryptApp struct {
	cApp
	r *privacy.Reader
}

func (d *decryptApp) GetPassphrase() (err error) {
	var (
		passphrase string
	)

	if passphrase, err = d.term.ReadPassword("input passphrase: "); err != nil {
		return
	}

	d.passphrase = passphrase

	return
}

func (d *decryptApp) ProcessFiles() (err error) {
	var (
		src io.Reader
	)

	if f.IsBase64() {
		src = base64.NewDecoder(base64.StdEncoding, d.srcFile)
	} else {
		src = d.srcFile
	}

	d.r = privacy.NewPrivacyReaderWithKeyGen(src, f.KeyGen())
redo:
	if err = d.r.ReadMagic(); err != nil {
		if h, ok := err.(privacy.InvalidCipherMethod); ok {
			if err = SkipHint(h, src); err != nil {
				return fmt.Errorf("reading magic bytes: %w", err)
			}
			goto redo
		}
		return
	}

	if err = d.r.GenerateKey(d.passphrase); err != nil {
		return
	}

	if _, err = io.Copy(d.dstFile, d.r); err != nil {
		return
	}

	if err = d.dstFile.Close(); err != nil {
		return
	}

	if err = d.srcFile.Close(); err != nil {
		return
	}

	return
}
