package privacy

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
)

type chacha20 struct {
	aead    cipher.AEAD
	privacy *Privacy
	block   []byte
	blank   bool
	nonce   []byte
}

func newChaCha20(key []byte, p *Privacy) (c *chacha20, err error) {
	c = &chacha20{
		privacy: p,
	}

	c.aead, err = chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	c.nonce = make([]byte, c.aead.NonceSize())
	c.block = make([]byte, 0, c.aead.NonceSize()+int(p.GetSegmentSize())+c.aead.Overhead())
	c.blank = true

	return
}

func (c *chacha20) write(wc io.WriteCloser, inwr []byte) error {
	var err error
	if c.blank {
		_, err = rand.Read(c.nonce)
		if err != nil {
			return err
		}

		if len(inwr) > 0 {
			c.blank = false
		}
	}

	if len(c.block)+len(inwr) < int(c.privacy.GetSegmentSize()) {
		start := len(c.block)
		c.block = c.block[:start+len(inwr)]
		copy(c.block[start:], inwr)
		return nil
	} else if len(c.block)+len(inwr) == int(c.privacy.GetSegmentSize()) {
		start := len(c.block)
		c.block = c.block[:start+len(inwr)]
		copy(c.block[start:], inwr)

		lenSlot := make([]byte, 4)
		blockLen := uint32(len(c.block) + c.aead.Overhead())
		binary.BigEndian.PutUint32(lenSlot, blockLen)

		//TODO: fix and resume from here, it was a stopping point
		//result := c.aead.Seal(c.block[:0], c.nonce, c.block, lenSlot)
		c.aead.Seal(c.block[:0], c.nonce, c.block, lenSlot)
	}

	return nil
}
