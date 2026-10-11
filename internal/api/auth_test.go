package api

import (
	"testing"
)

func TestValidatePasswordPolicy(t *testing.T) {
	cases := []struct {
		name     string
		password string
		valid    bool
	}{
		{"TooShort", "Aa1!", false},
		{"NoUpper", "password123!", false},
		{"NoLower", "PASSWORD123!", false},
		{"NoNumber", "Password!@#$", false},
		{"NoSpecial", "Password1234", false},
		{"ValidPassword1", "Valtrivo@2026!", true},
		{"ValidPassword2", "Admin#5651Secure", true},
		{"ValidComplex", "Abc@9552!*", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePasswordPolicy(tc.password)
			if tc.valid && err != nil {
				t.Errorf("expected password '%s' to be valid, got error: %v", tc.password, err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expected password '%s' to fail validation, but it passed", tc.password)
			}
		})
	}
}
