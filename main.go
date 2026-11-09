package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"bufio"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	formatMagic = "BYANOVA1"
	publicKeyType = "BYANOVA X25519 PUBLIC KEY"
	privateKeyType = "BYANOVA X25519 PRIVATE KEY"
)

func main() {
	if len(os.Args) < 2 { if err := runConsole(); err != nil { fmt.Fprintln(os.Stderr, "bycr:", err); os.Exit(1) }; return }
	var err error
	switch os.Args[1] {
	case "console", "shell": err = runConsole()
	case "keygen": err = runKeygen(os.Args[2:])
	case "encrypt": err = runEncrypt(os.Args[2:])
	case "decrypt": err = runDecrypt(os.Args[2:])
	case "help", "-h", "--help": usage()
	default: usage(); err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil { fmt.Fprintln(os.Stderr, "byanova:", err); os.Exit(1) }
}

func usage() {
	fmt.Fprintln(os.Stderr, "BYANOVA — experimental file encryption\n\nUsage:\n  bycr                 start interactive console\n  bycr keygen [-private private.pem] [-public public.pem]\n  bycr encrypt -pub public.pem -in plaintext -out encrypted.bya\n  bycr decrypt -key private.pem -in encrypted.bya -out plaintext\n\nThe recipient's public key can be shared. Keep the private key secret.")
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	privPath := fs.String("private", "byanova_private.pem", "private key output")
	pubPath := fs.String("public", "byanova_public.pem", "public key output")
	if err := fs.Parse(args); err != nil { return err }
	if *privPath == *pubPath { return errors.New("private and public key paths must differ") }
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil { return fmt.Errorf("generate key: %w", err) }
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil { return fmt.Errorf("encode private key: %w", err) }
	pubDER, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
	if err != nil { return fmt.Errorf("encode public key: %w", err) }
	privPEM := pem.EncodeToMemory(&pem.Block{Type: privateKeyType, Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: publicKeyType, Bytes: pubDER})
	if err := writeNewFile(*privPath, privPEM, 0600); err != nil { return err }
	if err := writeNewFile(*pubPath, pubPEM, 0644); err != nil { _ = os.Remove(*privPath); return err }
	fmt.Printf("Wrote private key: %s\nWrote public key:  %s\n", *privPath, *pubPath)
	return nil
}

func runEncrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	pubPath := fs.String("pub", "", "recipient public key")
	inPath := fs.String("in", "", "input file")
	outPath := fs.String("out", "", "output file")
	if err := fs.Parse(args); err != nil { return err }
	if *pubPath == "" || *inPath == "" || *outPath == "" { return errors.New("encrypt requires -pub, -in and -out") }
	pub, err := loadPublicKey(*pubPath)
	if err != nil { return err }
	plaintext, err := os.ReadFile(*inPath)
	if err != nil { return fmt.Errorf("read input: %w", err) }
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil { return fmt.Errorf("generate ephemeral key: %w", err) }
	shared, err := eph.ECDH(pub)
	if err != nil { return fmt.Errorf("derive shared secret: %w", err) }
	key, err := deriveKey(shared)
	if err != nil { return fmt.Errorf("derive encryption key: %w", err) }
	aead, err := chacha20poly1305.NewX(key)
	if err != nil { return fmt.Errorf("initialize cipher: %w", err) }
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return fmt.Errorf("generate nonce: %w", err) }
	header := append([]byte(formatMagic), eph.PublicKey().Bytes()...)
	header = append(header, pub.Bytes()...)
	sealed := aead.Seal(nil, nonce, plaintext, header)
	output := make([]byte, 0, len(formatMagic)+32+len(nonce)+len(sealed))
	output = append(output, formatMagic...)
	output = append(output, eph.PublicKey().Bytes()...)
	output = append(output, nonce...)
	output = append(output, sealed...)
	if err := writeNewFile(*outPath, output, 0600); err != nil { return err }
	fmt.Printf("Encrypted %d bytes to %s\n", len(plaintext), *outPath)
	return nil
}

func runDecrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	keyPath := fs.String("key", "", "recipient private key")
	inPath := fs.String("in", "", "encrypted input file")
	outPath := fs.String("out", "", "plaintext output file")
	if err := fs.Parse(args); err != nil { return err }
	if *keyPath == "" || *inPath == "" || *outPath == "" { return errors.New("decrypt requires -key, -in and -out") }
	priv, err := loadPrivateKey(*keyPath)
	if err != nil { return err }
	data, err := os.ReadFile(*inPath)
	if err != nil { return fmt.Errorf("read input: %w", err) }
	minLen := len(formatMagic)+32+chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead
	if len(data) < minLen { return errors.New("encrypted file is too short or damaged") }
	if string(data[:len(formatMagic)]) != formatMagic { return errors.New("unknown file format or version") }
	offset := len(formatMagic)
	ephBytes := data[offset:offset+32]
	offset += 32
	nonce := data[offset:offset+chacha20poly1305.NonceSizeX]
	offset += chacha20poly1305.NonceSizeX
	ciphertext := data[offset:]
	ephPub, err := ecdh.X25519().NewPublicKey(ephBytes)
	if err != nil { return fmt.Errorf("invalid ephemeral public key: %w", err) }
	shared, err := priv.ECDH(ephPub)
	if err != nil { return fmt.Errorf("derive shared secret: %w", err) }
	key, err := deriveKey(shared)
	if err != nil { return fmt.Errorf("derive encryption key: %w", err) }
	aead, err := chacha20poly1305.NewX(key)
	if err != nil { return fmt.Errorf("initialize cipher: %w", err) }
	header := append([]byte(formatMagic), ephBytes...)
	header = append(header, priv.PublicKey().Bytes()...)
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil { return errors.New("authentication failed: wrong key or modified file") }
	if err := writeNewFile(*outPath, plaintext, 0600); err != nil { return err }
	fmt.Printf("Decrypted %d bytes to %s\n", len(plaintext), *outPath)
	return nil
}

func deriveKey(shared []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, nil, []byte("BYANOVA file encryption v1"))
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := io.ReadFull(r, key)
	return key, err
}

func loadPublicKey(path string) (*ecdh.PublicKey, error) {
	block, err := readPEM(path, publicKeyType)
	if err != nil { return nil, err }
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil { return nil, fmt.Errorf("parse public key: %w", err) }
	key, ok := parsed.(*ecdh.PublicKey)
	if !ok || key.Curve() != ecdh.X25519() { return nil, errors.New("public key is not X25519") }
	return key, nil
}

func loadPrivateKey(path string) (*ecdh.PrivateKey, error) {
	block, err := readPEM(path, privateKeyType)
	if err != nil { return nil, err }
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil { return nil, fmt.Errorf("parse private key: %w", err) }
	key, ok := parsed.(*ecdh.PrivateKey)
	if !ok || key.Curve() != ecdh.X25519() { return nil, errors.New("private key is not X25519") }
	return key, nil
}

func readPEM(path, expectedType string) (*pem.Block, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, fmt.Errorf("read key %s: %w", path, err) }
	block, rest := pem.Decode(data)
	if block == nil || block.Type != expectedType || len(rest) != 0 { return nil, fmt.Errorf("%s is not a valid %s PEM file", path, expectedType) }
	return block, nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil { return fmt.Errorf("create %s (refusing to overwrite): %w", path, err) }
	if _, err := f.Write(data); err != nil { _ = f.Close(); _ = os.Remove(path); return fmt.Errorf("write %s: %w", path, err) }
	if err := f.Sync(); err != nil { _ = f.Close(); _ = os.Remove(path); return fmt.Errorf("sync %s: %w", path, err) }
	if err := f.Close(); err != nil { _ = os.Remove(path); return fmt.Errorf("close %s: %w", path, err) }
	return nil
}


const (
	ansiReset = "\x1b[0m"
	ansiCyan = "\x1b[36m"
	ansiGreen = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed = "\x1b[31m"
	ansiBold = "\x1b[1m"
)

func runConsole() error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	printBanner()
	for {
		fmt.Printf("%sbycr>%s ", ansiGreen+ansiBold, ansiReset)
		if !scanner.Scan() { fmt.Println(); return scanner.Err() }
		line := strings.TrimSpace(scanner.Text())
		if line == "" { continue }
		fields := strings.Fields(line)
		command := strings.ToLower(fields[0])
		args := fields[1:]
		switch command {
		case "exit", "quit", "выход":
			fmt.Println(ansiCyan + "BYANOVA session closed. Stay safe." + ansiReset)
			return nil
		case "clear", "cls":
			fmt.Print("\033[2J\033[H")
			printBanner()
		case "help", "?", "помощь":
			printHelp()
		case "version":
			fmt.Println("BYANOVA-CRYPTO v1 · file format BYANOVA1 · experimental")
		case "keygen":
			if err := runKeygen(args); err != nil { printConsoleError(err) }
		case "encrypt":
			if err := runEncrypt(args); err != nil { printConsoleError(err) }
		case "decrypt":
			if err := runDecrypt(args); err != nil { printConsoleError(err) }
		default:
			fmt.Printf("%sUnknown command:%s %s — type %shelp%s\n", ansiRed, ansiReset, fields[0], ansiCyan, ansiReset)
		}
	}
}

func printBanner() {
	fmt.Println()
	fmt.Printf("%s%s╭──────────────────────────────────────────────╮%s\n", ansiCyan, ansiBold, ansiReset)
	fmt.Printf("%s%s│           BYANOVA  /  CRYPTO CONSOLE         │%s\n", ansiCyan, ansiBold, ansiReset)
	fmt.Printf("%s%s╰──────────────────────────────────────────────╯%s\n", ansiCyan, ansiBold, ansiReset)
	fmt.Printf("  %sSecure tools. Simple commands. v1%s\n", ansiYellow, ansiReset)
	fmt.Printf("  Type %shelp%s to see commands, %sexit%s to quit.\n\n", ansiGreen, ansiReset, ansiGreen, ansiReset)
}

func printHelp() {
	fmt.Println()
	fmt.Printf("%sAVAILABLE COMMANDS%s\n", ansiBold, ansiReset)
	fmt.Printf("  %skeygen%s   [ -private FILE ] [ -public FILE ]   Generate X25519 keys\n", ansiGreen, ansiReset)
	fmt.Printf("  %sencrypt%s  -pub FILE -in FILE -out FILE          Encrypt a file\n", ansiGreen, ansiReset)
	fmt.Printf("  %sdecrypt%s  -key FILE -in FILE -out FILE          Decrypt a file\n", ansiGreen, ansiReset)
	fmt.Printf("  %sversion%s                                      Show version\n", ansiGreen, ansiReset)
	fmt.Printf("  %sclear%s                                        Clear the screen\n", ansiGreen, ansiReset)
	fmt.Printf("  %shelp%s                                         Show this help\n", ansiGreen, ansiReset)
	fmt.Printf("  %sexit%s                                         Close the console\n\n", ansiGreen, ansiReset)
	fmt.Println("Examples:")
	fmt.Println("  keygen")
	fmt.Println("  encrypt -pub byanova_public.pem -in notes.txt -out notes.bya")
	fmt.Println("  decrypt -key byanova_private.pem -in notes.bya -out notes-restored.txt")
	fmt.Printf("\n%sSecurity:%s experimental, unaudited software. See the README.\n\n", ansiYellow, ansiReset)
}

func printConsoleError(err error) {
	fmt.Printf("%s✗ %v%s\n", ansiRed, err, ansiReset)
}
