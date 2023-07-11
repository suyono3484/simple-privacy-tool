package privacy

import (
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
	"os"
)

func GenerateKey(password string) ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt[1:])
	if err != nil {
		return nil, err
	}

	key := argon2.IDKey([]byte(password), salt, 1, 16*1024, 4, 32)

	return key, nil
}

func ReadPasswordFromTerminal() (string, error) {
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
