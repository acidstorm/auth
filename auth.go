package auth

import (
	"github.com/HairyMezican/goauth2/oauth"
	"github.com/martini-contrib/sessionauth"

	// "github.com/jmcvetta/randutil"
	"encoding/json"
	"errors"
	"fmt"
)

type Auth struct {
	ProviderName string
	Token        string
	ProviderID   string `json:"id"`
	UserID       string
	Email        string `json:"email"`
	Password     []byte
}

type User struct {
	UserID      string
	UserName    string
	DisplayName string
	Email       string
}

func GenerateAnonymousUser() sessionauth.User {
	return &User{}
}
func (this *User) GetById() {
	return this.UserID
}

var FacebookConfig = &oauth.Config{
	ClientId:     "",
	ClientSecret: "",
	Scope:        "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
	AuthURL:      "https://accounts.google.com/o/oauth2/auth",
	TokenURL:     "https://accounts.google.com/o/oauth2/token",
	RedirectURL:  "",
}
var GoogleConfig = &oauth.Config{
	ClientId:     "",
	ClientSecret: "",
	Scope:        "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
	AuthURL:      "https://accounts.google.com/o/oauth2/auth",
	TokenURL:     "https://accounts.google.com/o/oauth2/token",
	RedirectURL:  "",
}

func InitStrategy(provider string, clientID string, ClientSecret string, RedirectURL string) {
	switch provider {
	case "google":
		InitGoogleStrategy(clientID, ClientSecret, RedirectURL)
		break
	case "facebook":
		InitFacebookStrategy(clientID, ClientSecret, RedirectURL)
		break
	default:
	}
}
func InitFacebookStrategy(clientID string, ClientSecret string, RedirectURL string) {
	FacebookConfig.ClientId = clientID
	FacebookConfig.ClientSecret = ClientSecret
	FacebookConfig.RedirectURL = RedirectURL
	fmt.Printf("\nInitializing Facebook Strategy\n")
}

func InitGoogleStrategy(clientID string, ClientSecret string, RedirectURL string) {
	GoogleConfig.ClientId = clientID
	GoogleConfig.ClientSecret = ClientSecret
	GoogleConfig.RedirectURL = RedirectURL
	fmt.Printf("\nInitializing Google Strategy\n")
}

func GetAuthenticationURL(provider string, path string) (url string, err error) {
	switch provider {
	case "google":
		url = GoogleConfig.AuthCodeURL(url)
		break
	case "facebook":
		url = FacebookConfig.AuthCodeURL(url)
		break
	default:
		err = errors.New("")
		// "Provider not found"
	}
	return
}

func SubmitToken(provider string, code string, profileURL string) (user User, err error) {
	var config *oauth.Config
	switch provider {
	case "google":
		config = GoogleConfig
		break
	case "facebook":
		config = FacebookConfig
		break
	default:
		err = errors.New("Provider not found")
	}
	t := &oauth.Transport{Config: config}
	t.Exchange(code)
	fmt.Printf("\nToken: %#v\n", t)
	resp, err := t.Client().Get(profileURL)
	if err != nil {
		return
	}
	buf := make([]byte, 2048)
	n, err := resp.Body.Read(buf)
	fmt.Printf("\n %d:  %s\n", n, string(buf[:n]))
	if err != nil {
		return
	}
	if err = json.Unmarshal(buf[:n], &user); err != nil {
		return
	}
	return
}

// func (this *User) isUnique() bool {

// }
