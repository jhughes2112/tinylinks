package auth

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"tinyauth/internal/types"
	"tinyauth/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/rs/zerolog/log"
)

type Auth struct {
	Config types.AuthConfig
	Store  *sessions.CookieStore
}

func NewAuth(config types.AuthConfig) *Auth {
	// Setup cookie store and create the auth service
	store := sessions.NewCookieStore([]byte(config.HMACSecret), []byte(config.EncryptionSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   config.SessionExpiry,
		Secure:   config.CookieSecure,
		HttpOnly: true,
		Domain:   fmt.Sprintf(".%s", config.Domain),
	}
	return &Auth{Config: config, Store: store}
}

func (auth *Auth) GetSession(c *gin.Context) (*sessions.Session, error) {
	session, err := auth.Store.Get(c.Request, auth.Config.SessionCookieName)

	// If there was an error getting the session, it might be invalid so let's clear it and retry
	if err != nil {
		log.Error().Err(err).Msg("Invalid session, clearing cookie and retrying")
		c.SetCookie(auth.Config.SessionCookieName, "", -1, "/", fmt.Sprintf(".%s", auth.Config.Domain), auth.Config.CookieSecure, true)
		session, err = auth.Store.Get(c.Request, auth.Config.SessionCookieName)
		if err != nil {
			log.Error().Err(err).Msg("Failed to get session")
			return nil, err
		}
	}

	return session, nil
}

func (auth *Auth) CreateSessionCookie(c *gin.Context, data *types.SessionCookie) error {
	log.Debug().Msg("Creating session cookie")

	session, err := auth.GetSession(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get session")
		return err
	}

	log.Debug().Msg("Setting session cookie")

	session.Values["username"] = data.Username
	session.Values["name"] = data.Name
	session.Values["email"] = data.Email
	session.Values["provider"] = data.Provider
	session.Values["expiry"] = time.Now().Add(time.Duration(auth.Config.SessionExpiry) * time.Second).Unix()
	session.Values["oauthGroups"] = data.OAuthGroups

	err = session.Save(c.Request, c.Writer)
	if err != nil {
		log.Error().Err(err).Msg("Failed to save session")
		return err
	}

	return nil
}

func (auth *Auth) DeleteSessionCookie(c *gin.Context) error {
	log.Debug().Msg("Deleting session cookie")

	session, err := auth.GetSession(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get session")
		return err
	}

	// Delete all values in the session
	for key := range session.Values {
		delete(session.Values, key)
	}

	err = session.Save(c.Request, c.Writer)
	if err != nil {
		log.Error().Err(err).Msg("Failed to save session")
		return err
	}

	return nil
}

func (auth *Auth) GetSessionCookie(c *gin.Context) (types.SessionCookie, error) {
	log.Debug().Msg("Getting session cookie")

	session, err := auth.GetSession(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get session")
		return types.SessionCookie{}, err
	}

	log.Debug().Msg("Got session")

	username, usernameOk := session.Values["username"].(string)
	email, emailOk := session.Values["email"].(string)
	name, nameOk := session.Values["name"].(string)
	provider, providerOK := session.Values["provider"].(string)
	expiry, expiryOk := session.Values["expiry"].(int64)
	oauthGroups, oauthGroupsOk := session.Values["oauthGroups"].(string)

	// If any data is missing, delete the session cookie
	if !usernameOk || !providerOK || !expiryOk || !emailOk || !nameOk || !oauthGroupsOk {
		log.Warn().Msg("Session cookie is invalid")
		auth.DeleteSessionCookie(c)
		return types.SessionCookie{}, nil
	}

	// If the session cookie has expired, delete it
	if time.Now().Unix() > expiry {
		log.Warn().Msg("Session cookie expired")
		auth.DeleteSessionCookie(c)
		return types.SessionCookie{}, nil
	}

	log.Debug().Str("username", username).Str("provider", provider).Int64("expiry", expiry).Str("name", name).Str("email", email).Str("oauthGroups", oauthGroups).Msg("Parsed cookie")
	return types.SessionCookie{
		Username:    username,
		Name:        name,
		Email:       email,
		Provider:    provider,
		OAuthGroups: oauthGroups,
	}, nil
}

func (auth *Auth) ResourceAllowed(c *gin.Context, context types.UserContext, labels types.Labels) bool {
	if context.OAuth {
		return true
	}
	return false
}

func (auth *Auth) OAuthGroup(c *gin.Context, context types.UserContext, labels types.Labels) bool {
	if labels.OAuth.Groups == "" {
		return true
	}

	// Check if we are using the generic oauth provider
	if context.Provider != "generic" {
		log.Debug().Msg("Not using generic provider, skipping group check")
		return true
	}

	// Split the groups by comma (no need to parse since they are from the API response)
	oauthGroups := strings.Split(context.OAuthGroups, ",")

	// For every group check if it is in the required groups
	for _, group := range oauthGroups {
		if utils.CheckFilter(labels.OAuth.Groups, group) {
			log.Debug().Str("group", group).Msg("Group is in required groups")
			return true
		}
	}

	// No groups matched
	log.Debug().Msg("No groups matched")
	return false
}

func (auth *Auth) AuthEnabled(uri string, labels types.Labels) (bool, error) {
	// If the label is empty, auth is enabled
	if labels.Allowed == "" {
		return true, nil
	}

	// Compile regex
	regex, err := regexp.Compile(labels.Allowed)

	// If there is an error, invalid regex, auth enabled
	if err != nil {
		log.Error().Err(err).Msg("Invalid regex")
		return true, err
	}

	// If the regex matches the URI, auth is not enabled
	if regex.MatchString(uri) {
		return false, nil
	}

	// Auth enabled
	return true, nil
}

func (auth *Auth) CheckIP(labels types.Labels, ip string) bool {
	// Check if the IP is in block list
	for _, blocked := range labels.IP.Block {
		res, err := utils.FilterIP(blocked, ip)
		if err != nil {
			log.Error().Err(err).Str("item", blocked).Msg("Invalid IP/CIDR in block list")
			continue
		}
		if res {
			log.Warn().Str("ip", ip).Str("item", blocked).Msg("IP is in blocked list, denying access")
			return false
		}
	}

	// For every IP in the allow list, check if the IP matches
	for _, allowed := range labels.IP.Allow {
		res, err := utils.FilterIP(allowed, ip)
		if err != nil {
			log.Error().Err(err).Str("item", allowed).Msg("Invalid IP/CIDR in allow list")
			continue
		}
		if res {
			log.Debug().Str("ip", ip).Str("item", allowed).Msg("IP is in allowed list, allowing access")
			return true
		}
	}

	// If not in allowed range and allowed range is not empty, deny access
	if len(labels.IP.Allow) > 0 {
		log.Warn().Str("ip", ip).Msg("IP not in allow list, denying access")
		return false
	}

	log.Debug().Str("ip", ip).Msg("IP not in allow or block list, allowing by default")
	return true
}

func (auth *Auth) BypassedIP(labels types.Labels, ip string) bool {
	// For every IP in the bypass list, check if the IP matches
	for _, bypassed := range labels.IP.Bypass {
		res, err := utils.FilterIP(bypassed, ip)
		if err != nil {
			log.Error().Err(err).Str("item", bypassed).Msg("Invalid IP/CIDR in bypass list")
			continue
		}
		if res {
			log.Debug().Str("ip", ip).Str("item", bypassed).Msg("IP is in bypass list, allowing access")
			return true
		}
	}

	log.Debug().Str("ip", ip).Msg("IP not in bypass list, continuing with authentication")
	return false
}
