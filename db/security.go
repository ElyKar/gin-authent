package db

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"reflect"
)

// ComputeHash computes the hash of a salted password provided
// the right informations. The computing is basic: sha512(salt+password).
// A better way would be to use bcrypt. An even better way would be
// to use something like hmac and iterate a few times (10,000 is a good start).
func computeHash(password string, salt string) string {
	value := []byte(salt + password)
	hash := sha512.Sum512(value)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// GenerateSalt creates a random salt using Golang's builtin
// cryptographic pseudo-random number generator
// Salt is fixed to 16 bytes (128 bits), which is defined as
// good practice
func generateSalt() (string, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// SetUserPassword updates a user's information given a new password
// user should be a pointer to the user model
// It updates the salt and hash to be stored in the database
// It updates ONLY those two fields and leave the others untouched
// Note that it does not persist anything into the database
func SetUserPassword(user interface{}, newPassword string) error {
	val := reflect.ValueOf(user).Elem()
	salt, err := generateSalt()
	if err != nil {
		return err
	}

	hash := computeHash(newPassword, salt)
	val.FieldByName("Hash").SetString(hash)
	val.FieldByName("Salt").SetString(salt)
	return nil
}

// CheckUser returns true if the user has submitted the correct
// password, or a generic error otherwise.
func checkUser(user reflect.Value, password string) (bool, error) {
	salt := user.FieldByName("Salt").String()
	hash := computeHash(password, salt)
	if hash == user.FieldByName("Hash").String() {
		return true, nil
	}

	return false, errors.New("Invalid attempt for username/password")
}
