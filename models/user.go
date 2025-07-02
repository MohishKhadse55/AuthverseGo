package models

var Users = map[string]string{
	"mohish": "password@123",
	"alice":  "qwerty",
	"bob":    "letmein",
}

func ValidateUser(username, password string) bool {
	if pass, exists := Users[username]; exists {
		return pass == password
	}
	return false
}
