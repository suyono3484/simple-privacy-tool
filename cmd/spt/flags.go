package spt

import (
	"errors"
	"gitea.suyono.dev/suyono/simple-privacy-tool/privacy"
)

type flags struct {
	base64Encoding  bool
	algo            string
	cmType          privacy.CipherMethodType
	kdf             string
	argon2idTime    int
	argon2idMemory  int
	argon2idThreads int
	keygen          privacy.KeyGen
	hint            bool
}

const (
	defaultAlgo  = ""
	chacha20Algo = "chacha"
	aesAlgo      = "aes"

	defaultKdf  = defaultAlgo
	argon2idKdf = "argon2"

	argon2idTime    = 1
	argon2idMemory  = 64 * 1024
	argon2idThreads = 4
)

var (
	f flags
)

func initFlags() {
	encryptCmd.PersistentFlags().BoolVar(&f.hint, "hint", false, "include hint in the output file")
	encryptCmd.PersistentFlags().StringVar(&f.algo, "algo", defaultAlgo, "encryption algorithm, valid values: chacha and aes. Default algo is chacha")
	rootCmd.PersistentFlags().StringVar(&f.kdf, "kdf", defaultKdf, "Key Derivation Function, valid values: argon2")
	rootCmd.PersistentFlags().IntVar(&f.argon2idTime, "argon2id-time", argon2idTime, "sets argon2id time cost-parameter")
	rootCmd.PersistentFlags().IntVar(&f.argon2idMemory, "argon2id-mem", argon2idMemory, "sets argon2id memory cost-parameter (in KB)")
	rootCmd.PersistentFlags().IntVar(&f.argon2idThreads, "argon2id-thread", argon2idThreads, "sets argon2id thread cost-parameter")
	rootCmd.PersistentFlags().BoolVar(&f.base64Encoding, "base64", false, "the file is encoded in Base64")
}

func processFlags() (err error) {
	if err = processAlgoFlags(); err != nil {
		return
	}

	if err = processKeyGenFlags(); err != nil {
		return
	}

	return
}

func processAlgoFlags() (err error) {
	switch f.algo {
	case defaultAlgo, chacha20Algo:
		f.cmType = privacy.XChaCha20Simple
	case aesAlgo:
		f.cmType = privacy.AES256GCMSimple
	default:
		return errors.New("invalid algo")
	}

	return
}

func processKeyGenFlags() (err error) {
	switch f.kdf {
	case defaultKdf:
		f.keygen = privacy.NewArgon2()
	case argon2idKdf:
		if f.argon2idTime < 0 || f.argon2idThreads < 0 || f.argon2idMemory < 0 {
			return errors.New("invalid argon2id parameter")
		}
		f.keygen, err = privacy.NewArgon2WithParams(uint32(f.argon2idTime), uint32(f.argon2idMemory), uint8(argon2idThreads))
	default:
		return errors.New("invalid KDF")
	}

	return
}

func (f flags) IsBase64() bool {
	return f.base64Encoding
}

func (f flags) CipherMethod() privacy.CipherMethodType {
	return f.cmType
}

func (f flags) KeyGen() privacy.KeyGen {
	return f.keygen
}

func (f flags) IncludeHint() bool {
	return f.hint
}
