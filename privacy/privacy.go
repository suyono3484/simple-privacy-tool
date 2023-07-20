package privacy

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

type CipherMethodType byte

const (
	segmentSizeBytesLen int = 4

	Uninitialised   CipherMethodType = 0
	XChaCha20Simple CipherMethodType = 1

	DefaultCipherMethod CipherMethodType = XChaCha20Simple
)

var (
	ErrInvalidSaltLen       = errors.New("invalid salt length")
	ErrUninitialisedMethod  = errors.New("cipher method type uninitialised")
	ErrInvalidCipherMethod  = errors.New("invalid cipher method type")
	ErrCannotReadMagicBytes = errors.New("cannot read magic bytes")
	ErrInvalidReadFlow      = errors.New("func ReadMagic should be called before calling Read")
	ErrInvalidKeyState      = errors.New("func GenerateKey should be called first")
	ErrInvalidSegmentLength = errors.New("segment length is too long")
)

type Reader struct {
	*Privacy
	reader   io.Reader
	buf      []byte
	bufSlice []byte
}

type WriteCloser struct {
	*Privacy
	writeCloser  io.WriteCloser
	buf          []byte
	bufSlice     []byte
	magicWritten bool
}

type Privacy struct {
	salt        []byte
	segmentSize uint32
	cmType      CipherMethodType
	aead        cipher.AEAD
}

func newPrivacy() *Privacy {
	return &Privacy{
		segmentSize: 64 * 1024 * 1024,
		cmType:      Uninitialised,
	}
}

func NewPrivacyReader(reader io.Reader) *Reader {
	return &Reader{
		Privacy: newPrivacy(),
		reader:  reader,
	}
}

func NewPrivacyWriteCloser(wc io.WriteCloser, cmType CipherMethodType) *WriteCloser {
	privacy := newPrivacy()
	privacy.cmType = cmType
	return &WriteCloser{
		Privacy:      privacy,
		writeCloser:  wc,
		magicWritten: false,
	}
}

func (p *Privacy) SetSalt(salt []byte) error {
	if len(salt) != 16 {
		return ErrInvalidSaltLen
	}

	if len(p.salt) != 16 {
		p.salt = make([]byte, 16)
	}

	copy(p.salt, salt)

	return nil
}

func (p *Privacy) GetSegmentSize() uint32 {
	return p.segmentSize
}

func (p *Privacy) SetSegmentSize(size uint32) {
	p.segmentSize = size
}

func (p *Privacy) NewSalt() error {
	if len(p.salt) != 16 {
		p.salt = make([]byte, 16)
	}

	if p.cmType == Uninitialised {
		return ErrUninitialisedMethod
	}

	p.salt[0] = byte(p.cmType)
	_, err := rand.Read(p.salt[1:])
	if err != nil {
		return err
	}

	return nil
}

func (p *Privacy) GenerateKey(passphrase string) error {
	var (
		key []byte
		err error
	)

	if p.cmType == Uninitialised {
		return ErrUninitialisedMethod
	}

	key = argon2.IDKey([]byte(passphrase), p.salt, 1, 16*1024, 4, 32)
	switch p.cmType {
	case XChaCha20Simple:
		p.aead, err = chacha20poly1305.NewX(key)
	default:
		return ErrInvalidCipherMethod
	}
	if err != nil {
		return err
	}

	return nil
}

func (wc *WriteCloser) Write(b []byte) (n int, err error) {
	var (
		// segmentLen      uint32
		// segmentLenBytes []byte
		// nonce           []byte
		// ciphertext      []byte
		// plaintext       []byte
		copied int
	)

	if wc.aead == nil {
		return 0, ErrInvalidKeyState
	}

	if cap(wc.buf) != int(wc.segmentSize)+wc.aead.NonceSize()+wc.aead.Overhead() {
		wc.buf = make([]byte, int(wc.segmentSize)+wc.aead.NonceSize()+wc.aead.Overhead())
		wc.bufSlice = wc.buf[wc.aead.NonceSize():wc.aead.NonceSize()]
	}

	if !wc.magicWritten {
		n, err = wc.writeCloser.Write(wc.salt)
		if err != nil {
			return
		}
		wc.magicWritten = true
	}

	copied = 0
	for copied < len(b) {
		if len(wc.bufSlice) == int(wc.segmentSize) {

		} else {
			if len(b[copied:]) <= int(wc.segmentSize)-len(wc.bufSlice) {
				wc.bufSlice = wc.buf[wc.aead.NonceSize() : len(wc.bufSlice)+len(b[copied:])]
			}
		}
	}

	return
}

func (r *Reader) ReadMagic() (err error) {
	if r.cmType == Uninitialised {
		magic := make([]byte, 16)
		_, err = r.reader.Read(magic[:1])
		if err != nil {
			return
		}

		switch CipherMethodType(magic[0]) {
		case XChaCha20Simple:
			r.cmType = XChaCha20Simple
			_, err = r.reader.Read(magic[1:])
			if err != nil {
				return
			}

			err = r.SetSalt(magic)
			if err != nil {
				return
			}
		default:
			return ErrInvalidCipherMethod
		}

	}

	return nil
}

func (r *Reader) Read(b []byte) (n int, err error) {
	var (
		segmentLen      uint32
		segmentLenBytes []byte
		nonce           []byte
		ciphertext      []byte
		plaintext       []byte
		copied          int
	)

	if r.cmType == Uninitialised {
		return 0, ErrInvalidReadFlow
	}

	if r.aead == nil {
		return 0, ErrInvalidKeyState
	}

	if cap(r.buf) != int(r.segmentSize)+r.aead.Overhead()+r.aead.NonceSize() {
		r.buf = make([]byte, int(r.segmentSize)+r.aead.Overhead()+r.aead.NonceSize())
	}

	copied = 0
	for copied < len(b) {
		if len(r.bufSlice) == 0 {
			//TODO: nothing in the buffer, fill it up
			segmentLenBytes = make([]byte, segmentSizeBytesLen)
			n, err = r.reader.Read(segmentLenBytes)
			if err != nil {
				return
			}

			segmentLen = binary.LittleEndian.Uint32(segmentLenBytes)
			if segmentLen > r.segmentSize {
				return 0, ErrInvalidSegmentLength
			}

			n, err = r.reader.Read(r.buf)
			if err != nil {
				return
			}

			nonce = r.buf[:r.aead.NonceSize()]
			ciphertext = r.buf[r.aead.NonceSize():]
			plaintext = ciphertext[:0]

			r.bufSlice, err = r.aead.Open(plaintext, nonce, ciphertext, segmentLenBytes)
			if err != nil {
				return
			}
		} else {
			if len(b)-copied <= len(r.bufSlice) {
				copy(b[copied:], r.bufSlice[:len(b)-copied])
				r.bufSlice = r.bufSlice[len(b)-copied:]
				copied += len(b) - copied
			} else {
				copy(b[copied:], r.bufSlice)
				copied += len(r.bufSlice)
				r.bufSlice = r.bufSlice[:0]
			}
		}
	}

	return copied, nil
}

func ReadPassphraseFromTerminal() (string, error) {
	var inputFd int = int(os.Stdin.Fd())
	if !term.IsTerminal(inputFd) {
		return "", errors.New("not a terminal")
	}

	passwd, err := term.ReadPassword(inputFd)
	if err != nil {
		return "", err
	}

	return string(passwd), nil
}
