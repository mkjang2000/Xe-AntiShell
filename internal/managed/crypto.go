package managed

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

func GenerateSigningKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func EncodePublicKey(key ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(key) }

func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid signing public key")
	}
	return ed25519.PublicKey(key), nil
}

func signValue(kind, keyID string, value any, private ed25519.PrivateKey, maximum int) (string, error) {
	if len(private) != ed25519.PrivateKeySize {
		return "", errors.New("invalid signing private key")
	}
	input, err := signatureInput(kind, keyID, value, maximum)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, input)), nil
}

func verifyValue(kind, keyID string, value any, signature string, trusted map[string]ed25519.PublicKey, maximum int) error {
	key := trusted[keyID]
	if len(key) != ed25519.PublicKeySize {
		return errors.New("untrusted signing key")
	}
	input, err := signatureInput(kind, keyID, value, maximum)
	if err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(decoded) != ed25519.SignatureSize || !ed25519.Verify(key, input, decoded) {
		return errors.New("invalid signature")
	}
	return nil
}

func signatureInput(kind, keyID string, value any, maximum int) ([]byte, error) {
	if !validIdentifier(keyID, 128) {
		return nil, errors.New("invalid signing key ID")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(body) > maximum {
		return nil, errors.New("signed value exceeds its size limit")
	}
	// Domain separation prevents a grant from being interpreted as policy and
	// binds key identity as well as every field of the typed payload.
	prefix := []byte("xe-antishell-managed/v1/" + kind + "\x00" + keyID + "\x00")
	return append(prefix, body...), nil
}
