package main

// Authenticater holds the authentification process, whichever it is.
type Authenticater interface {
	// Authenticate a user, given its login and password. The interface{} returned should be a pointer to the underlying model of your user.
	Authenticate(login, password string) (interface{}, error)
}
