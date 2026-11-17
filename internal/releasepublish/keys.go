package releasepublish

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/mkjang2000/Xe-AntiShell/protocol/managed"
)

type PublicPublisher struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

func Public(private ed25519.PrivateKey) PublicPublisher {
	pub := private.Public().(ed25519.PublicKey)
	hash := sha256.Sum256(pub)
	return PublicPublisher{KeyID: "release-" + hex.EncodeToString(hash[:8]), PublicKey: managed.EncodePublicKey(pub)}
}

func GenerateKey(directory string) (PublicPublisher, error) {
	if os.MkdirAll(directory, 0o700) != nil {
		return PublicPublisher{}, errors.New("cannot create private signing directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return PublicPublisher{}, errors.New("signing directory must be private")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return PublicPublisher{}, errors.New("signing directory must belong to this user")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PublicPublisher{}, errors.New("cannot generate signing key")
	}
	defer clear(private)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return PublicPublisher{}, errors.New("cannot encode signing key")
	}
	defer clear(der)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(encoded)
	if err = writeExclusive(filepath.Join(directory, "publisher-key.pem"), encoded, 0o600); err != nil {
		return PublicPublisher{}, err
	}
	public := Public(private)
	if err = WriteJSON(filepath.Join(directory, "publisher-public.json"), public, 0o644); err != nil {
		return PublicPublisher{}, err
	}
	return public, nil
}

func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 16<<10 {
		return nil, errors.New("signing key must be a private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, errors.New("signing key ownership is not trusted")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("cannot open signing key")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("signing key changed during read")
	}
	data, err := io.ReadAll(io.LimitReader(file, 16<<10+1))
	defer clear(data)
	if err != nil || len(data) > 16<<10 {
		return nil, errors.New("cannot read signing key")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) > 0 {
		return nil, errors.New("signing key must be PKCS8 Ed25519 PEM")
	}
	defer clear(block.Bytes)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid signing key")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key must be Ed25519")
	}
	return key, nil
}
