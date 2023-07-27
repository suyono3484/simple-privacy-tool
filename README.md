# simple-privacy-tool

Simple Privacy Tool is a simple tool to encrypt and decrypt files. It uses the symmetric algorithm XChaCha20-Poly1305 and
AES-GCM, and Argon2id for the key derivation function.

Since this tool uses a symmetric algorithm, the level of privacy hinges solely on the password's strength. So, make sure
to choose your password carefully.


### Build
```shell
go build
```
or install with `go install gitea.suyono.dev/suyono/simple-privacy-tool`

### Usage
By default simple-privacy-tool uses XChaCha20-Poly1305.

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
`simple-privacy-tool` can operate on `STDIN` or `STDOUT`. Just replace the file path with `-`
```shell
tar -zcf - dir | simple-privacy-tool encrypt - - | another-command
```

Special usage, just omit both file paths to use `STDIN` and `STDOUT`.
```shell
tar -zcf - dir | simple-privacy-tool encrypt | another-command
```

#### Customize Argon2id parameter
The simple-privacy-tool accepts several flags to tweak Argon2id parameters. There are three parameters that user can
adjust: time, memory, and threads. Example
```shell
simple-privacy-tool encrypt --kdf argon2 --argon2id-time 2 --argon2id-mem 65536 --argon2id-thread 4 --hint inputFile outputFile
```
The user has to include `--kdf` flag to be able to customize the parameter. Optionally, user can add `--hint` flag to embed
the custom parameter in the encrypted file as a hint. Warning: the hint in the encrypted file is not protected (authenticated)
and the decryption process doesn't use the hint.

The purpose of the hint is as human reminder. User can print the embedded hint by using command
```shell
simple-privacy-tool hint encryptedFile
```
