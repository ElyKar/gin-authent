package db

import (
	"reflect"

	"github.com/jinzhu/gorm"
)

// User is the base struct representing a user in the database.
type User struct {
	gorm.Model        // The model containing stuff like id
	Username   string `gorm:"type:varchar(100);unique_index"` // Username, if any
	Salt       string `gorm:"not null"`                       // Salt of the password, in base64
	Hash       string `gorm:"not null"`                       // Hash of the salt + password, in base64
	Mail       string `gorm:"type:varchar(100);unique_index"` // Mail address of the user
}

type DbAuthenticater struct {
	db *gorm.DB // The database connection

	// LookForMail is set to true if we have to find users based on their
	// mail, false if we look for their username.
	lookForMail bool

	typ reflect.Type // The user type, used as a model for the fetched instances

}

// NewDbAuthenticater returns anew authenticater. It takes a connection to the database as input. If lookForMail is set to true, then user will be logged in according to their mail address, else their username will be used. The interface in argument is the model used for the user. It should contain the base user of the package as an anonymous field.
func NewDbAuthenticater(db *gorm.DB, lookForMail bool, inter interface{}) *DbAuthenticater {
	typ := reflect.TypeOf(inter)
	// Check if we have a struct or ptr to struct
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	return &DbAuthenticater{db, lookForMail, typ}
}

// Authenticate fetches a user from the database, based on its identifier (username OR mail) and password. It returns a couple (User,nil) if found, or (nil,error) if not.
func (auth *DbAuthenticater) Authenticate(login, password string) (interface{}, error) {
	res := reflect.New(auth.typ)
	if auth.lookForMail {
		auth.db.Where("mail = ?", login).First(res.Interface())
	} else {
		auth.db.Where("username = ?", login).First(res.Interface())
	}

	_, err := checkUser(res.Elem(), password)
	if err != nil {
		return nil, err
	}
	return res.Interface(), nil
}
