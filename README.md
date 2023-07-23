# simple-privacy-tool

Simple Privacy Tool is a simple tool to encrypt and decrypt files. It uses the symmetric algorithm XChaCha-Poly1305 and
Argon2id for the key derivation function.

Since this tool uses a symmetric algorithm, the level of privacy hinges solely on the password's strength. So, make sure
to choose your password carefully.

### Build

```shell
go build
```

### Usage

#### Encrypt
Encrypting `plainfile` to `cryptedfile`
```shell
simple-privacy-tool encrypt plainfile cryptedfile
```

#### Decrypt
Decrypting `cryptedfile` back to `plainfile`
```shell
simple-privacy-tool decrypt cryptedfile plainfile
```

#### Using STDIN/STDOUT
`simple-privacy-tool` can operate on `STDOUT`. Just replace the file path with `-`
```shell
simple-privacy-tool encrypt srcFile - | another-command
```
