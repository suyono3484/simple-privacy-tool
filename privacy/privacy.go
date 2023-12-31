package privacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

type CipherMethodType byte

type KeyGen interface {
	json.Marshaler
	GenerateKey(password, salt []byte) []byte
}

const (
	segmentSizeBytesLen int = 4

	Uninitialised   CipherMethodType = 0x00
	XChaCha20Simple CipherMethodType = 0x01
	AES256GCMSimple CipherMethodType = 0x02

	DefaultCipherMethod = XChaCha20Simple
)

var (
	ErrInvalidSaltLen      = errors.New("invalid salt length")
	ErrUninitialisedSalt   = errors.New("uninitialised salt")
	ErrUninitialisedMethod = errors.New("cipher method type uninitialised")
	//ErrCannotReadMagicBytes = errors.New("cannot read magic bytes")	//no usage for now
	ErrInvalidReadFlow      = errors.New("func ReadMagic should be called before calling Read")
	ErrInvalidKeyState      = errors.New("func GenerateKey should be called first")
	ErrInvalidSegmentLength = errors.New("segment length is too long")
	segmentLenBytes         = make([]byte, segmentSizeBytesLen)
)

type InvalidCipherMethod []byte

func (i InvalidCipherMethod) Error() string {
	return "invalid cipher method type"
}

type Reader struct {
	*Privacy
	reader   io.Reader
	buf      []byte
	bufSlice []byte
	isEOF    bool
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
	keygen      KeyGen
}

func newPrivacy(k KeyGen) *Privacy {
	return &Privacy{
		segmentSize: 64 * 1024 * 1024,
		cmType:      Uninitialised,
		keygen:      k,
	}
}

func NewPrivacyReader(reader io.Reader) *Reader {
	return NewPrivacyReaderWithKeyGen(reader, NewArgon2())
}

func NewPrivacyReaderWithKeyGen(reader io.Reader, keygen KeyGen) *Reader {
	return &Reader{
		Privacy: newPrivacy(keygen),
		reader:  reader,
		isEOF:   false,
	}
}

func NewPrivacyWriterCloserDefault(wc io.WriteCloser) *WriteCloser {
	return NewPrivacyWriteCloser(wc, DefaultCipherMethod)
}

func NewPrivacyWriteCloser(wc io.WriteCloser, cmType CipherMethodType) *WriteCloser {
	return NewPrivacyWriteCloserWithKeyGen(wc, cmType, NewArgon2())
}

func NewPrivacyWriteCloserWithKeyGen(wc io.WriteCloser, cmType CipherMethodType, keygen KeyGen) *WriteCloser {
	privacy := newPrivacy(keygen)
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

	if len(p.salt) != 16 {
		return ErrUninitialisedSalt
	}

	key = p.keygen.GenerateKey([]byte(passphrase), p.salt)
	switch p.cmType {
	case XChaCha20Simple:
		if p.aead, err = chacha20poly1305.NewX(key); err != nil {
			return err
		}
	case AES256GCMSimple:
		var block cipher.Block
		if block, err = aes.NewCipher(key); err != nil {
			return err
		}
		if p.aead, err = cipher.NewGCM(block); err != nil {
			return err
		}
	default:
		return InvalidCipherMethod([]byte{})
	}

	return nil
}

func (wc *WriteCloser) Write(b []byte) (n int, err error) {
	var (
		copied     int
		nonceSize  int
		lastMarker int
		plaintext  []byte
	)

	if wc.aead == nil {
		return 0, ErrInvalidKeyState
	}

	if cap(wc.buf) != int(wc.segmentSize)+wc.aead.NonceSize()+wc.aead.Overhead() {
		wc.buf = make([]byte, int(wc.segmentSize)+wc.aead.NonceSize()+wc.aead.Overhead())
		wc.bufSlice = wc.buf[wc.aead.NonceSize():wc.aead.NonceSize()]
	}

	if !wc.magicWritten {
		n, err = wc.writeUp(wc.salt)
		if err != nil {
			return
		}
		wc.magicWritten = true
	}

	nonceSize = wc.aead.NonceSize()
	copied = 0
	for copied < len(b) {
		if len(wc.bufSlice) == int(wc.segmentSize) {
			n, err = wc.writeSegment()
			if err != nil {
				return
			}
		} else {
			lastMarker = len(wc.bufSlice)
			plaintext = wc.buf[nonceSize : nonceSize+len(wc.bufSlice)]
			if len(b[copied:]) <= int(wc.segmentSize)-len(wc.bufSlice) {
				plaintext = plaintext[:len(plaintext)+len(b[copied:])]
				copied += copy(plaintext[lastMarker:], b[copied:])
			} else {
				plaintext = plaintext[:int(wc.segmentSize)]
				copied += copy(plaintext[lastMarker:], b[copied:])
			}
			wc.bufSlice = plaintext
		}
	}

	return copied, nil
}

func (wc *WriteCloser) writeSegment() (n int, err error) {
	var (
		nonce      []byte
		ciphertext []byte
		plaintext  []byte
		written    int
	)

	written = len(wc.bufSlice)
	binary.LittleEndian.PutUint32(segmentLenBytes, uint32(written))
	n, err = wc.writeUp(segmentLenBytes)
	if err != nil {
		return
	}

	nonce = wc.buf[:wc.aead.NonceSize()]
	_, err = rand.Read(nonce)
	if err != nil {
		return
	}
	plaintext = wc.buf[wc.aead.NonceSize() : wc.aead.NonceSize()+written]
	ciphertext = plaintext[:0]

	wc.aead.Seal(ciphertext, nonce, plaintext, segmentLenBytes)
	n, err = wc.writeUp(wc.buf[:written+wc.aead.NonceSize()+wc.aead.Overhead()])
	if err != nil {
		return
	}
	wc.bufSlice = wc.buf[wc.aead.NonceSize():wc.aead.NonceSize()]

	return written, nil
}

func (wc *WriteCloser) writeUp(b []byte) (n int, err error) {
	var (
		total int
	)

	for {
		if n, err = wc.writeCloser.Write(b[total:]); err != nil {
			return n + total, err
		}

		total += n
		if total == len(b) {
			break
		}
	}

	return total, nil
}

func (wc *WriteCloser) Close() (err error) {
	if len(wc.bufSlice) > 0 {
		_, err = wc.writeSegment()
		if err != nil {
			return
		}
	}
	return wc.writeCloser.Close()
}

func (r *Reader) ReadMagic() (err error) {
	if r.cmType == Uninitialised {
		magic := make([]byte, 16)
		if _, err = r.readUp(magic); err != nil {
			return
		}

		switch CipherMethodType(magic[0]) {
		case XChaCha20Simple:
			r.cmType = XChaCha20Simple
		case AES256GCMSimple:
			r.cmType = AES256GCMSimple
		default:
			return InvalidCipherMethod(magic)
		}

		if err = r.SetSalt(magic); err != nil {
			return
		}
	}

	return nil
}

func (r *Reader) readUp(b []byte) (n int, err error) {
	var (
		total int
	)

	for {
		if n, err = r.reader.Read(b[total:]); err != nil {
			return n + total, err
		}

		total += n
		if total == len(b) {
			break
		}
	}

	return total, nil
}

func (r *Reader) Read(b []byte) (n int, err error) {
	var (
		segmentLen uint32
		nonce      []byte
		ciphertext []byte
		plaintext  []byte
		copied     int
	)

	if r.cmType == Uninitialised {
		return 0, ErrInvalidReadFlow
	}

	if r.aead == nil {
		return 0, ErrInvalidKeyState
	}

	if r.isEOF {
		return 0, io.EOF
	}

	if cap(r.buf) != int(r.segmentSize)+r.aead.Overhead()+r.aead.NonceSize() {
		r.buf = make([]byte, int(r.segmentSize)+r.aead.Overhead()+r.aead.NonceSize())
	}

	//log.Printf("Read for %d bytes\n", len(b))
	copied = 0
	for copied < len(b) {
		if len(r.bufSlice) == 0 {
			n, err = r.readUp(segmentLenBytes)
			if err != nil {
				if err == io.EOF {
					if copied > 0 {
						r.isEOF = true
						return copied, nil
					} else {
						r.isEOF = true
						return 0, err
					}
				}
				return
			}

			segmentLen = binary.LittleEndian.Uint32(segmentLenBytes)
			if segmentLen > r.segmentSize {
				return 0, ErrInvalidSegmentLength
			}

			n, err = r.readUp(r.buf[:int(segmentLen)+r.aead.Overhead()+r.aead.NonceSize()])
			if err != nil {
				return
			}

			nonce = r.buf[:r.aead.NonceSize()]
			ciphertext = r.buf[r.aead.NonceSize() : r.aead.NonceSize()+int(segmentLen)+r.aead.Overhead()]
			plaintext = ciphertext[:0]

			if _, err = r.aead.Open(plaintext, nonce, ciphertext, segmentLenBytes); err != nil {
				return copied, fmt.Errorf("decrypt Read: %w", err)
			}
			plaintext = plaintext[:int(segmentLen)]
			r.bufSlice = plaintext
		} else {
			if len(b[copied:]) <= len(r.bufSlice) {
				cp := copy(b[copied:], r.bufSlice)
				r.bufSlice = r.bufSlice[cp:]
				copied += cp
			} else {
				copied += copy(b[copied:], r.bufSlice)
				r.bufSlice = r.buf[r.aead.NonceSize():r.aead.NonceSize()]
			}
		}
	}

	n = copied
	return
}
