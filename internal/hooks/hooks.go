package hooks

import (
	"tinyauth/internal/auth"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

type Hooks struct {
	Config    types.HooksConfig
	Auth      *auth.Auth
	Providers *providers.Providers
}

func NewHooks(config types.HooksConfig, auth *auth.Auth, providers *providers.Providers) *Hooks {
	return &Hooks{Config: config, Auth: auth, Providers: providers}
}

func (hooks *Hooks) UseUserContext(c *gin.Context) types.UserContext {
	cookie, err := hooks.Auth.GetSessionCookie(c)
	if err != nil || cookie.Provider == "" {
		log.Error().Err(err).Msg("Failed to get session cookie")
		return types.UserContext{}
	}

	provider := hooks.Providers.GetProvider(cookie.Provider)
	if provider == nil {
		return types.UserContext{}
	}

	return types.UserContext{
		Username:    cookie.Username,
		Name:        cookie.Name,
		Email:       cookie.Email,
		IsLoggedIn:  true,
		OAuth:       true,
		Provider:    cookie.Provider,
		OAuthGroups: cookie.OAuthGroups,
	}
}
