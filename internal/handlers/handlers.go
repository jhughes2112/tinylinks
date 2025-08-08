package handlers

import (
	"strings"
	"sync"
	"time"
	"tinyauth/internal/auth"
	"tinyauth/internal/docker"
	"tinyauth/internal/hooks"
	"tinyauth/internal/linkdb"
	"tinyauth/internal/providers"
	"tinyauth/internal/types"

	"github.com/gin-gonic/gin"
)

type Handlers struct {
	Config    types.HandlersConfig
	Auth      *auth.Auth
	Hooks     *hooks.Hooks
	Providers *providers.Providers
	Docker    *docker.Docker
	LinkDB    *linkdb.DB
	admin     map[string]struct{}
	codeMu    sync.Mutex
	codes     map[string]codeEntry
}

type codeEntry struct {
	Issuer  string
	Expires time.Time
}

func NewHandlers(config types.HandlersConfig, auth *auth.Auth, hooks *hooks.Hooks, providers *providers.Providers, docker *docker.Docker, db *linkdb.DB, admins []string) *Handlers {
	adminMap := make(map[string]struct{})
	for _, e := range admins {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			adminMap[e] = struct{}{}
		}
	}
	return &Handlers{
		Config:    config,
		Auth:      auth,
		Hooks:     hooks,
		Providers: providers,
		Docker:    docker,
		LinkDB:    db,
		admin:     adminMap,
		codes:     make(map[string]codeEntry),
	}
}

func (h *Handlers) HealthcheckHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
	})
}
