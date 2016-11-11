package main

import (
	"errors"

	"github.com/gin-gonic/gin"
)

const (
	// CookieName is the key under which the cookie will be stored client-side
	CookieName = "sessid"
	// ContextKey is used to retrieve the user from the gin context in user-defined handlers
	ContextKey = "gin-sessid"
)

// Auth is the front structure of the application. Basically, it delegates everything to the security module, which itself delegates the authentication process to the given authenticater.
type Auth struct {
	// A Pointer to the underlying security module
	sec *securityModule
}

// NewAuth creates a new auth from the auth method.
func NewAuth(authenticater Authenticater) *Auth {
	return &Auth{&securityModule{authenticater,
		make(map[string]*Session)}}
}

// Middleware is the handler to add to the gin handler chain. It will be called before each of the actual handlers for the routes. Basically, it retrieves the cookie CookieName from the request, and assert the user is properly authenticated. If not, then the response code will be set to 401. Gin offers the possibility to check such things. If the user is properly authenticated, then it is added to gin's context under the key ContextKey.
func (auth *Auth) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Cookie(CookieName)

		if err != nil {
			// No cookie, no access
			c.AbortWithStatus(401)
			return
		}

		// No session, no access
		session := auth.sec.getSession(cookie)
		if session == nil {
			c.AbortWithStatus(401)
			return
		}

		// Found the session, update it and pass the user to
		// the other contexts
		session.update()
		c.Set(ContextKey, session.user)

	}
}

// LoginWithAbort tries to log in a user given his credentials. If invalid, then the response code will be set to 401, if not, the user is returned
func (auth *Auth) LoginWithAbort(login, password string, c *gin.Context) interface{} {
	user, err := auth.LoginWithErr(login, password, c)

	if err != nil {
		c.AbortWithStatus(401)
		return nil
	}

	return user
}

// LoginWithErr tries to log in a user given his credentials. If invalid, an error is returned. If not, the user is returned
func (auth *Auth) LoginWithErr(login, password string, c *gin.Context) (interface{}, error) {
	user, err := auth.sec.getUser(login, password)

	if err != nil {
		return nil, err
	}

	sess := auth.sec.createSession(user)
	c.SetCookie(CookieName, sess.sessID, 0, "", c.Request.Host, false, false)
	return sess.user, nil
}

// Disconnect a user. It returns an error if the user was not authenticated before, else nil.
func (auth *Auth) Disconnect(c *gin.Context) error {
	cookie, err := c.Cookie(CookieName)

	if err != nil {
		// No cookie, nothing to do
		return err
	}

	// No session, nothing to do
	session := auth.sec.getSession(cookie)
	if session == nil {
		return errors.New("User was not authenticated")
	}

	auth.sec.deleteSession(cookie)
	return nil
}
