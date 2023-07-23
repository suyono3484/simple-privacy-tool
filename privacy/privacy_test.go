package privacy

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	mr "math/rand"
	"testing"
)

type tBuffer struct {
	buf  []byte
	rOff int
}

func newTBuf(size int) *tBuffer {
	return &tBuffer{
		buf: make([]byte, 0, size),
	}
}

func (tb *tBuffer) Read(b []byte) (n int, err error) {
	if tb.rOff == len(tb.buf) {
		return 0, io.EOF
	}

	if len(b)+tb.rOff <= len(tb.buf) {
		copy(b, tb.buf[tb.rOff:])
		tb.rOff += len(b)
		return len(b), nil
	} else {
		copy(b[:len(tb.buf)-tb.rOff], tb.buf[tb.rOff:])
		n = len(tb.buf) - tb.rOff
		err = nil
		tb.rOff = len(tb.buf)
		return
	}
}

func (tb *tBuffer) Write(b []byte) (n int, err error) {
	if len(tb.buf)+len(b) > cap(tb.buf) {
		return 0, errors.New("insufficient space")
	}

	wOff := len(tb.buf)
	tb.buf = tb.buf[:wOff+len(b)]
	copy(tb.buf[wOff:], b)
	return len(b), nil
}

func (tb *tBuffer) Close() error {
	return nil
}

func TestReadWriteClose(t *testing.T) {
	tb := newTBuf(70 * 1024)
	keygen, err := NewArgon2WithParams(1, 4*1024, 2)
	if err != nil {
		t.Fatal("test preparation failure:", err)
	}

	passphrase := "some passphrase"

	writer := NewPrivacyWriteCloserWithKeyGen(tb, DefaultCipherMethod, keygen)

	t.Run("uninitialised salt", func(t *testing.T) {
		err = writer.GenerateKey(passphrase)
		if err == nil {
			t.Fatal("unexpected: it should error")
		}
		if err != ErrUninitialisedSalt {
			t.Fatal("unexpected error result:", err)
		}
	})

	writer.SetSegmentSize(uint32(16 * 1024))

	if err = writer.NewSalt(); err != nil {
		t.Fatal("unexpected: NewSalt failed", err)
	}
	if err = writer.GenerateKey(passphrase); err != nil {
		t.Fatal("unexpected: failed to generate key", err)
	}

	sha := sha256.New()
	ur := mr.New(mr.NewSource(1))
	bb := make([]byte, 1048)

	var (
		//bar int
		n  int
		wl int
		rl int
	)
	for i := 0; i < 63; i++ {
		//bar = 1000 + ur.Intn(49)
		//ur.Read(bb[:bar])
		//sha.Write(bb[:bar])
		//if n, err = writer.Write(bb[:bar]); err != nil {
		//	t.Fatal("unexpected: Write failed", err)
		//}
		ur.Read(bb)
		sha.Write(bb)
		if n, err = writer.Write(bb); err != nil {
			t.Fatal("unexpected: Write failed", err)
		}
		wl += n
	}

	if err = writer.Close(); err != nil {
		t.Fatal("unexpected: Close failed", err)
	}

	writeHash := sha.Sum(nil)
	t.Log("write hash:", hex.EncodeToString(writeHash))

	reader := NewPrivacyReaderWithKeyGen(tb, keygen)
	reader.SetSegmentSize(uint32(16 * 1024))
	if err = reader.ReadMagic(); err != nil {
		t.Fatal("unexpected: ReadMagic failed", err)
	}

	if err = reader.GenerateKey(passphrase); err != nil {
		t.Fatal("unexpected: GenerateKey failed", err)
	}

	sha.Reset()
	err = nil
	n = 0
	for err == nil {
		if n, err = reader.Read(bb); err != nil {
			if err == io.EOF {
				continue
			} else {
				t.Fatal("unexpected: Read failed", err)
			}
		}
		rl += n
		sha.Write(bb)
	}

	readHash := sha.Sum(nil)
	t.Log("read hash:", hex.EncodeToString(readHash))

	t.Log("wl", wl)
	t.Log("rl", rl)
	for i := range writeHash {
		if readHash[i] != writeHash[i] {
			t.Fatal("unexpected: mismatch hash")
		}
	}
}

func TestTrial(t *testing.T) {
	x := make([]byte, 20)
	for i := range x {
		x[i] = byte(i)
	}

	t.Log("len x:", len(x))
	t.Log("cap x:", cap(x))
	t.Log("x:", x)

	y := x[5:13]
	t.Log("len y:", len(y))
	t.Log("cap y:", cap(y))
	t.Log("y:", y)

	z := y[10:15]
	t.Log("len z:", len(z))
	t.Log("cap z:", cap(z))
	t.Log("z:", z)
}

func TestKeyGen(t *testing.T) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	passphrase := []byte("some passphrase")

	key := argon2.IDKey(passphrase, salt, 1000, 64*1024, 8, 32)

	_ = key
	//keyCompare := argon2Params.IDKey(passphrase, salt, 100, 64*1024, 4, 32)
	//
	//for i := range key {
	//	if key[i] != keyCompare[i] {
	//		t.Fatal("unexpected result")
	//	}
	//}
}

func TestExample(t *testing.T) {
	passphrase := []byte("some passphrase")
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatal("error prepare salt", err)
	}

	key := argon2.IDKey(passphrase, salt, 1, 4*1024, 2, 32)

	var aead cipher.AEAD
	if aead, err = chacha20poly1305.NewX(key); err != nil {
		t.Fatal("chacha", err)
	}

	ur := mr.New(mr.NewSource(1))
	bb := make([]byte, 1024+aead.NonceSize()+aead.Overhead())

	if _, err = rand.Read(bb[:aead.NonceSize()]); err != nil {
		t.Fatal("fill up nonce", err)
	}

	additional := []byte("some additional data")
	ur.Read(bb[aead.NonceSize() : aead.NonceSize()+1024])
	before := sha256.Sum256(bb[aead.NonceSize() : aead.NonceSize()+1024])

	aead.Seal(bb[aead.NonceSize():aead.NonceSize()], bb[:aead.NonceSize()], bb[aead.NonceSize():aead.NonceSize()+1024], additional)

	if _, err = aead.Open(bb[aead.NonceSize():aead.NonceSize()],
		bb[:aead.NonceSize()], bb[aead.NonceSize():aead.NonceSize()+1024+aead.Overhead()],
		additional); err != nil {
		t.Fatal("decrypt error", err)
	}

	after := sha256.Sum256(bb[aead.NonceSize() : aead.NonceSize()+1024])

	for i := range before {
		if before[i] != after[i] {
			t.Fatal("data corruption?")
		}
	}
}
