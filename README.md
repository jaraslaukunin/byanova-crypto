# BYANOVA-CRYPTO

**BYANOVA** is an experimental, cross-platform Go file-encryption CLI with an interactive terminal console named **BYCR**.

> **Security status:** experimental reference implementation. It has not undergone an independent cryptographic audit and should not be relied on for high-value or safety-critical data.

## Install (Linux / macOS)

Install Go 1.23+ first: https://go.dev/dl/

~~~sh
curl -fsSL https://raw.githubusercontent.com/jaraslaukunin/byanova-crypto/main/install.sh | sh
~~~

The installer downloads the source, builds the bycr executable, installs it into ~/.local/bin, and adds that directory to the detected shell startup file (bash, zsh, or fish). Open a new terminal after installation.

Start the interactive console:

~~~sh
bycr
~~~

Or show help:

~~~sh
bycr help
~~~

## Windows

Install Go 1.23+, then build from a clone:

~~~powershell
git clone https://github.com/jaraslaukunin/byanova-crypto.git
cd byanova-crypto
go mod download
go build -o bycr.exe .
~~~

Add the folder containing bycr.exe to your Windows PATH.

## Console commands

Inside the BYCR console:

- keygen — generate a recipient key pair
- encrypt -pub FILE -in FILE -out FILE — encrypt a file
- decrypt -key FILE -in FILE -out FILE — decrypt a file
- help, version, clear, exit

The same commands can be run directly from your normal terminal:

~~~sh
bycr keygen
bycr encrypt -pub byanova_public.pem -in notes.txt -out notes.bya
bycr decrypt -key byanova_private.pem -in notes.bya -out notes-restored.txt
~~~

## Cryptography

- X25519 for ephemeral-recipient key agreement
- HKDF-SHA-256 for deriving a 256-bit encryption key
- XChaCha20-Poly1305 for authenticated encryption
- A fresh ephemeral X25519 key and random 192-bit nonce for each encryption

The versioned file format is BYANOVA1. The format header and recipient public key are authenticated as associated data. Decryption fails if the ciphertext or authenticated header is modified.

## Important limitations

- **No sender authentication:** anyone with the recipient's public key can create a valid encrypted file. This format does not prove who sent it.
- **No forward secrecy against later recipient-key compromise:** a recorded file can be decrypted if the recipient's long-term private key is later compromised.
- **No replay protection or message history:** this is file encryption, not a messaging or delivery system.
- **Private-key storage:** the PEM private key is not password-encrypted. Protect it with operating-system permissions and secure storage.
- **No formal audit:** use established, audited tools and protocols for sensitive production use.

Do not invent or modify cryptographic primitives. Any protocol or format change should receive expert review and a new version identifier.

## CI

GitHub Actions runs tests, go vet, and a build on Linux, macOS, and Windows for pushes and pull requests to main.

## License

MIT. See LICENSE.
