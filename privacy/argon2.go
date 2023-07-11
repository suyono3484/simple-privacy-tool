package privacy

import (
	"encoding/json"
	"errors"
	"golang.org/x/crypto/argon2"
)

type argon2Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	Name    string
}

var ErrInvalidParameter = errors.New("invalid parameter")

const argon2KeyGenName = "argon2"

func (a argon2Params) GenerateKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, 32)
}

func NewArgon2() KeyGen {
	return argon2Params{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 4,
		Name:    argon2KeyGenName,
	}
}

func NewArgon2WithParams(time, memory uint32, threads uint8) (k KeyGen, err error) {
	if time == 0 || memory == 0 || threads == 0 {
		return nil, ErrInvalidParameter
	}

	return argon2Params{
		Time:    time,
		Memory:  memory,
		Threads: threads,
		Name:    argon2KeyGenName,
	}, nil
}

func (a argon2Params) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"name":    a.Name,
		"memory":  a.Memory,
		"threads": a.Threads,
		"time":    a.Time,
	}
	return json.Marshal(&m)
}
