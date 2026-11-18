package webpanel

import (
	"errors"
	"unicode/utf8"
)

// ValidateNewPassword applies only when creating/replacing a password. Existing
// credentials are verified without applying a newer composition policy.
func ValidateNewPassword(password string) error {
	if !utf8.ValidString(password) || len(password) > 1024 || utf8.RuneCountInString(password) < 8 {
		return errors.New("password must contain at least 8 Unicode characters and at most 1024 UTF-8 bytes")
	}
	var lower, upper, digit, special bool
	for _, value := range password {
		switch {
		case value >= 'a' && value <= 'z':
			lower = true
		case value >= 'A' && value <= 'Z':
			upper = true
		case value >= '0' && value <= '9':
			digit = true
		case value >= '!' && value <= '~':
			special = true
		}
	}
	if !lower || !digit || !special {
		return errors.New("password requires an ASCII lowercase letter, a digit and a special character")
	}
	if utf8.RuneCountInString(password) < 10 && !upper {
		return errors.New("passwords of 8 or 9 characters additionally require an ASCII uppercase letter")
	}
	return nil
}
