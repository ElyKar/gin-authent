package db

import "github.com/jinzhu/gorm"

// User is the base struct representing a user in the database.
type User struct {
	gorm.Model        // The model containing stuff like id
	Username   string `gorm:"type:varchar(100);unique_index"` // Username, if any
	Salt       string `gorm:"not null"`                       // Salt of the password, in base64
	Hash       string `gorm:"not null"`                       // Hash of the salt + password, in base64
	Mail       string `gorm:"type:varchar(100);unique_index"` // Mail address of the user
	Rights     uint   // The rights this user has
}

type DbAuthenticater struct {
	Db *gorm.DB // The database connection

	// LookForMail is set to true if we have to find users based on their
	// mail, false if we look for their username.
	LookForMail bool
}

// Authenticate fetches a user from the database, based on its identifier (username OR mail) and password. It returns a couple (*User,nil) if found, or (nil,error) if not.
func (auth *DbAuthenticater) Authenticate(login, password string) (interface{}, error) {
	res := &User{}
	if auth.LookForMail {
		auth.Db.Where("mail = ?", login).First(res)
	} else {
		auth.Db.Where("username = ?", login).First(res)
	}

	_, err := checkUser(res, password)
	if err != nil {
		return nil, err
	}
	return res, nil
}
