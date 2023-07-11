package spt

import (
	"fmt"
	"gitea.suyono.dev/suyono/simple-privacy-tool/privacy"
	"io"
	"os"
)

type decryptApp struct {
	cApp
	r *privacy.Reader
}

type stdoutWrapper struct {
	file *os.File
}

func newDecryptApp(a *cApp) *decryptApp {
	return &decryptApp{
		cApp: *a,
	}
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
	d.r = privacy.NewPrivacyReader(d.srcFile)
	if err = d.r.ReadMagic(); err != nil {
		return
	}

	if err = d.r.GenerateKey(d.passphrase); err != nil {
		return
	}

	if d.dstPath == "-" || d.srcPath == "-" {
		w := stdoutWrapper{
			file: d.dstFile,
		}
		if _, err = io.Copy(w, d.r); err != nil {
			return
		}
	} else {
		if _, err = io.Copy(d.dstFile, d.r); err != nil {
			return
		}
	}

	if err = d.dstFile.Close(); err != nil {
		return
	}

	if err = d.srcFile.Close(); err != nil {
		return
	}

	return
}

func (sw stdoutWrapper) ReadFrom(reader io.Reader) (n int64, err error) {
	var (
		nr   int
		rErr error
	)
	buf := make([]byte, 32768)

	for {
		if nr, err = reader.Read(buf); err != nil {
			break
		}

		n += int64(nr)
		if _, err = sw.file.Write(buf[:nr]); err != nil {
			return n, fmt.Errorf("readfrom internal write: %w", err)
		}
	}

	rErr = err
	if nr > 0 {
		n += int64(nr)
		if nr > 32768 {
			return n, fmt.Errorf("last piece length %d: %w", nr, err)
		}
		if _, err = sw.file.Write(buf[:nr]); err != nil {
			return n, fmt.Errorf("readfrom internal write: %w", err)
		}
	}

	if rErr == io.EOF || rErr == nil {
		err = nil
	} else {
		err = rErr
	}

	return
}

func (sw stdoutWrapper) Write(b []byte) (n int, err error) {
	return sw.file.Write(b)
}
