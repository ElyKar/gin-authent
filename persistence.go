package main

import (
	"crypto/rand"
	"encoding/base64"
	"time"
)

const SESSID_SIZE = 32

// Session represents a backend session.
type Session struct {
	user     interface{} // The user for the session
	sessID   string      // Randomly generated session id
	lastUsed time.Time   // Last time the user connected
}

// update the session, so it isn't discarded (cleaning is not implemented yet)
func (session *Session) update() {
	session.lastUsed = time.Now()
}

// securityModule handles the storage of the session, and communicates with the database
type securityModule struct {
	auth Authenticater // The authentification method to use

	sessions map[string]*Session // Identify each session with its sessid

}

// getUser tries to authenticate a user given the authenticater. Refer to the documentation of the authenticater used for a more specific description of the results
func (sec *securityModule) getUser(login string, password string) (interface{}, error) {
	return sec.auth.Authenticate(login, password)
}

// getSession uses the value of the cookie to get the appropriate session. If the cookie is unknown, then nil is returned.
func (sec *securityModule) getSession(cookie string) *Session {
	session, exists := sec.sessions[cookie]
	if exists {
		return session
	}
	return nil
}

// createSession makes a new session for a given user. It assumes the user has already logged in.
func (sec *securityModule) createSession(user interface{}) *Session {
	id := make([]byte, SESSID_SIZE)
	_, err := rand.Read(id)
	if err != nil {
		return nil
	}

	// Avoid any encoding problems this way
	sessID := base64.StdEncoding.EncodeToString(id)

	session := &Session{user, sessID, time.Now()}
	sec.sessions[sessID] = session

	return session
}

// deleteSession deletes the session for the cookie. Nothing is returned, may it have been found or not.
func (sec *securityModule) deleteSession(cookie string) {
	delete(sec.sessions, cookie)
}
