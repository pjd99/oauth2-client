package util

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type User struct {
	UserID       int          `json:"userid"` 
	FirstName    string       `json:"first"`
	LastName     string       `json:"last"`
	UserName     string       `json:"user"`
	Email        string       `json:"email"`
	Scope        string       `json:"scope"`
	Admin        bool         `json:"admin"`
	UserApps     []string     `json:"userapps"`
}

func GetUsers(auth string, authurl string) ([]*User, error) {
	uri := fmt.Sprintf("%s/users", authurl)
	req, err := NewRequestWithAuth(auth, "GET", uri, nil)
	if err != nil {
		fmt.Errorf("Unable to form users request: " + err.Error())
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Errorf("Unable to get users: " + err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to get users: %s", resp.Status)
	}

	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	var users []*User
	err = decoder.Decode(&users)
	if err != nil {
		fmt.Errorf("Failed to read users: " + err.Error())
	}

	return users, nil
}

func GetUser(auth string, authurl string, userID string) (*User, error) {
	uri := fmt.Sprintf("%s/user/%s", authurl, userID)
	req, err := NewRequestWithAuth(auth, "GET", uri, nil)
	if err != nil {
		fmt.Errorf("Unable to form user request: " + err.Error())
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Errorf("Unable to get user: " + err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to get user: %s", resp.Status)
	}

	defer resp.Body.Close()
	decoder := json.NewDecoder(resp.Body)
	var user *User
	err = decoder.Decode(&user)
	if err != nil {
		fmt.Errorf("Failed to read user: " + err.Error())
	}

	return user, nil
}
