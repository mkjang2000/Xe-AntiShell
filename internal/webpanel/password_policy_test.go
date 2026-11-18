package webpanel

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestNewPasswordCompositionAndRuneBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, password string
		valid          bool
	}{
		{"eight", "Abcd12!x", true},
		{"nine", "Abcde12!x", true},
		{"ten without uppercase", "abcdefg12!", true},
		{"ten with uppercase", "Abcdefg12!", true},
		{"seven", "Abc12!x", false},
		{"eight without uppercase", "abcd12!x", false},
		{"nine without uppercase", "abcde12!x", false},
		{"no lowercase", "ABCDEFG12!", false},
		{"no digit", "Abcdefgh!x", false},
		{"no special", "Abcdefg123", false},
		{"space is not special", "abcdefg12 ", false},
		{"unicode plus composition", "가나다라마abc1!", true},
		{"unicode eight requires uppercase", "가나다라ab1!", false},
		{"unicode eight with uppercase", "가나다라aB1!", true},
		{"unicode extra space", "abcd ef12!", true},
		{"invalid UTF8", "Abcd12!x\xff", false},
		{"max bytes", strings.Repeat("x", 1021) + "a1!", true},
		{"over max bytes", strings.Repeat("x", 1022) + "a1!", false},
		{"unicode over byte max", strings.Repeat("가", 341) + "a1!", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if valid := ValidateNewPassword(test.password) == nil; valid != test.valid {
				t.Fatalf("password policy acceptance=%v want=%v", valid, test.valid)
			}
		})
	}
}

func TestShortNewPasswordAndLegacyLoginRemainUsable(t *testing.T) {
	credentials, err := GenerateCredentials("admin", "Abcd12!x", testParameters())
	if err != nil || !credentials.Verify("admin", "Abcd12!x") {
		t.Fatal("new eight-character credentials cannot log in", err)
	}
	legacyPassword := "correct-horse-battery-staple"
	if ValidateNewPassword(legacyPassword) == nil {
		t.Fatal("legacy fixture unexpectedly meets the new composition policy")
	}
	salt, _ := base64.RawURLEncoding.DecodeString(credentials.Salt)
	p := credentials.Parameters
	credentials.Hash = base64.RawURLEncoding.EncodeToString(argon2.IDKey([]byte(legacyPassword), salt, p.Time, p.Memory, p.Threads, p.KeyLen))
	if !credentials.Verify("admin", legacyPassword) {
		t.Fatal("a legacy credential was forced through the new creation policy")
	}
}

func TestGeneratedPasswordsRetainEntropyAndMeetPolicy(t *testing.T) {
	for i := 0; i < 128; i++ {
		password, err := GeneratePassword()
		if err != nil || ValidateNewPassword(password) != nil || len(password) != 35 {
			t.Fatal("generated password does not meet creation policy", err)
		}
		random, err := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(password, "a1!"))
		if err != nil || len(random) != 24 {
			t.Fatal("generated password lost original random bytes")
		}
	}
}
