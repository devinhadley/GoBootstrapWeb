package user

import "testing"

func TestGetCommonPasswords(t *testing.T) {
	t.Run("returns map with entries", testGetCommonPasswordsReturnsEntries)
}

func TestIsCommonPassword(t *testing.T) {
	t.Run("returns true for lowercase", testIsCommonPasswordLowercase)
	t.Run("returns true for mixed case", testIsCommonPasswordMixedCase)
	t.Run("returns false for unknown", testIsCommonPasswordUnknown)
}

func testGetCommonPasswordsReturnsEntries(t *testing.T) {
	passwords := getCommonPasswords()
	if len(passwords) == 0 {
		t.Fatal("expected getCommonPasswords to return entries")
	}
}

func testIsCommonPasswordLowercase(t *testing.T) {
	passwords := getCommonPasswords()
	if !passwords.isCommonPassword("password") {
		t.Fatal("expected lowercase password to be common")
	}
}

func testIsCommonPasswordMixedCase(t *testing.T) {
	passwords := getCommonPasswords()
	if !passwords.isCommonPassword("PaSsWoRd") {
		t.Fatal("expected mixed-case password to be common")
	}
}

func testIsCommonPasswordUnknown(t *testing.T) {
	passwords := getCommonPasswords()
	if passwords.isCommonPassword("this-password-should-not-exist-9f4e3c7a") {
		t.Fatal("expected unknown password to not be common")
	}
}
