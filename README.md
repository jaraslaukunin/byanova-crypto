# BYANOVA-CRYPTO

BYANOVA is an experimental cross-platform Go file-encryption CLI.

## Security status

This is an unaudited reference implementation, not a production security product. It uses X25519 ephemeral-recipient key agreement, HKDF-SHA-256, and XChaCha20-Poly1305 authenticated encryption.

Limitations: no sender authentication, no replay protection, and no forward secrecy after compromise of the recipient's long-term private key. Private keys are stored unencrypted in PEM files. Use audited tools for sensitive data.

## Build

Requires Go 1.23 or newer.

```sh
go mod download
go test ./...
go build -o byanova .
```

Windows: `go build -o byanova.exe .`

## Usage

```sh
go run . keygen
go run . encrypt -pub byanova_public.pem -in message.txt -out message.bya
go run . decrypt -key byanova_private.pem -in message.bya -out recovered.txt
```

Key generation creates `byanova_private.pem` (keep secret) and `byanova_public.pem` (shareable). The CLI refuses to overwrite output files.

## License

MIT. See LICENSE.
