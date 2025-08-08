package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"strings"
	"time"
)

func (h *Handlers) cleanupCodes() {
	now := time.Now()
	for k, v := range h.codes {
		if now.After(v.Expires) {
			delete(h.codes, k)
		}
	}
}

func (h *Handlers) GetShortLinkHandler(c *gin.Context) {
	user := h.Hooks.UseUserContext(c)
	if !user.IsLoggedIn {
		c.JSON(401, gin.H{"status": 401, "message": "Unauthorized"})
		return
	}
	h.codeMu.Lock()
	defer h.codeMu.Unlock()
	h.cleanupCodes()
	code := strings.Split(uuid.NewString(), "-")[0]
	h.codes[code] = codeEntry{Issuer: user.Username, Expires: time.Now().Add(time.Hour)}
	c.JSON(200, gin.H{"code": code})
}

type codeRequest struct {
	Code string `json:"code"`
}

type unlinkRequest struct {
	A string `json:"a"`
	B string `json:"b"`
}

func (h *Handlers) UseShortLinkHandler(c *gin.Context) {
	user := h.Hooks.UseUserContext(c)
	if !user.IsLoggedIn {
		c.JSON(401, gin.H{"status": 401, "message": "Unauthorized"})
		return
	}
	var req codeRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"status": 400, "message": "Bad Request"})
		return
	}
	h.codeMu.Lock()
	h.cleanupCodes()
	entry, ok := h.codes[req.Code]
	if !ok {
		h.codeMu.Unlock()
		c.JSON(400, gin.H{"status": 400, "message": "Invalid code"})
		return
	}
	delete(h.codes, req.Code)
	h.codeMu.Unlock()
	if err := h.LinkDB.AddLink(entry.Issuer, user.Username); err != nil {
		log.Error().Err(err).Msg("failed to add link")
		c.JSON(500, gin.H{"status": 500, "message": "Internal Server Error"})
		return
	}
	c.JSON(200, gin.H{"status": 200, "message": "Linked"})
}

func (h *Handlers) GetLinkedAccountsHandler(c *gin.Context) {
	user := h.Hooks.UseUserContext(c)
	if !user.IsLoggedIn {
		c.JSON(401, gin.H{"status": 401, "message": "Unauthorized"})
		return
	}
	links, err := h.LinkDB.Get(user.Username)
	if err != nil {
		log.Error().Err(err).Msg("failed to get links")
		c.JSON(500, gin.H{"status": 500, "message": "Internal Server Error"})
		return
	}
	c.JSON(200, gin.H{"accounts": links})
}

func (h *Handlers) AdminShowLinkedAccountsHandler(c *gin.Context) {
	user := h.Hooks.UseUserContext(c)
	if !h.isAdmin(user.Email) {
		c.JSON(403, gin.H{"status": 403, "message": "Forbidden"})
		return
	}
	account := c.Query("account")
	links, err := h.LinkDB.Get(account)
	if err != nil {
		log.Error().Err(err).Msg("failed to get links")
		c.JSON(500, gin.H{"status": 500, "message": "Internal Server Error"})
		return
	}
	c.JSON(200, gin.H{"accounts": links})
}

func (h *Handlers) AdminUnlinkAccountsHandler(c *gin.Context) {
	user := h.Hooks.UseUserContext(c)
	if !h.isAdmin(user.Email) {
		c.JSON(403, gin.H{"status": 403, "message": "Forbidden"})
		return
	}
	var req unlinkRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"status": 400, "message": "Bad Request"})
		return
	}
	if err := h.LinkDB.RemoveLink(req.A, req.B); err != nil {
		log.Error().Err(err).Msg("failed to remove link")
		c.JSON(500, gin.H{"status": 500, "message": "Internal Server Error"})
		return
	}
	c.JSON(200, gin.H{"status": 200, "message": "Unlinked"})
}

func (h *Handlers) isAdmin(email string) bool {
	_, ok := h.admin[strings.ToLower(email)]
	return ok
}
