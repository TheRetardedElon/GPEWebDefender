package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 3
	argonMemory  = 32 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword returns an encoded argon2id hash. Never log the input.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	), nil
}

// CheckPassword is constant-time for a given hash encoding.
func CheckPassword(hash, pw string) bool {
	salt, want, ok := parseHash(hash)
	if !ok {
		dummy := make([]byte, argonKeyLen)
		_ = argon2.IDKey([]byte(pw), dummy[:saltLen], argonTime, argonMemory, argonThreads, argonKeyLen)
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func parseHash(hash string) (salt, sum []byte, ok bool) {
	// $argon2id$v=19$m=32768,t=3,p=2$salt$hash
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, false
	}
	sum, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(sum) == 0 {
		return nil, nil, false
	}
	return salt, sum, true
}

func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func TokenHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// TokensEqual compares secrets in constant time via SHA-256 (equal-length digests).
func TokensEqual(a, b string) bool {
	ha := TokenHash(a)
	hb := TokenHash(b)
	return subtle.ConstantTimeCompare([]byte(ha), []byte(hb)) == 1
}

func ValidUsername(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func ValidPassword(pw, username string) error {
	if len(pw) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}
	if len(pw) > 256 {
		return fmt.Errorf("password too long")
	}
	if username != "" && strings.EqualFold(pw, username) {
		return fmt.Errorf("password must not match the username")
	}
	low := strings.ToLower(pw)
	for _, bad := range []string{"password", "123456789012", "changeme1234", "gpesiemadmin"} {
		if strings.Contains(low, bad) {
			return fmt.Errorf("password is too common")
		}
	}
	return nil
}
