package spt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"gitea.suyono.dev/suyono/simple-privacy-tool/privacy"
	"github.com/spf13/cobra"
	"io"
	"os"
)

var (
	ErrNotHint = errors.New("not a hint")
)

func SkipHint(b []byte, r io.Reader) (err error) {
	if b[0] != 0xFF {
		return ErrNotHint
	}
	hintLen := int(binary.LittleEndian.Uint16(b[1:3])) - 13 // 13 is hint minimum length, prevent overlapping with magic
	if hintLen > 0 {
		skip := make([]byte, hintLen)

		var (
			n, total int
		)
		for total < hintLen {
			if n, err = r.Read(skip); err != nil {
				return
			}
			total += n
		}
	}

	return
}

func WriteHint(k privacy.KeyGen, w io.Writer) (err error) {
	var (
		b     []byte
		bb    *bytes.Buffer
		total int
		n     int
	)

	if b, err = k.MarshalJSON(); err != nil {
		return
	}

	wb := make([]byte, 3)
	wb[0] = 0xFF
	if len(b) >= 13 {
		binary.LittleEndian.PutUint16(wb[1:], uint16(len(b)))
	} else {
		binary.LittleEndian.PutUint16(wb[1:], uint16(13))
	}
	bb = bytes.NewBuffer(make([]byte, 0))
	bb.Write(wb)
	bb.Write(b)

	if len(b) < 13 {
		bb.Write(make([]byte, 13-len(b)))
	}

	b = bb.Bytes()
	for total < len(b) {
		if n, err = w.Write(b[total:]); err != nil {
			return
		}
		total += n
	}
	return
}

func CmdReadHint(cmd *cobra.Command, args []string) (err error) {
	var (
		f    *os.File
		tb   []byte
		hLen int
	)

	if f, err = os.Open(args[0]); err != nil {
		return
	}

	tb = make([]byte, 3)
	if _, err = f.Read(tb); err != nil {
		return
	}

	if tb[0] != 0xFF {
		return ErrNotHint
	}

	hLen = int(binary.LittleEndian.Uint16(tb[1:]))
	tb = make([]byte, hLen)
	if _, err = f.Read(tb); err != nil {
		return
	}

	if hLen == 13 {
		for hLen > 0 {
			if tb[hLen-1] != 0 {
				break
			}
			hLen--
		}
	}

	fmt.Println("hint:", string(tb[:hLen]))

	return
}
