package types

import (
	"tinyauth/internal/oauth"
)

// OAuthProviders is the struct for the OAuth providers
type OAuthProviders struct {
	Github    *oauth.OAuth
	Google    *oauth.OAuth
	Microsoft *oauth.OAuth
}

// SessionCookie is the cookie for the session (exculding the expiry)
type SessionCookie struct {
	Username    string
	Name        string
	Email       string
	Provider    string
	OAuthGroups string
}

// UserContext is the context for the user
type UserContext struct {
	Username    string
	Name        string
	Email       string
	IsLoggedIn  bool
	OAuth       bool
	Provider    string
	OAuthGroups string
}
