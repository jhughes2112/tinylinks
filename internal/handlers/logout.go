package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (h *Handlers) LogoutHandler(c *gin.Context) {
	log.Debug().Msg("Cleaning up redirect cookie")
	h.Auth.DeleteSessionCookie(c)
	c.JSON(200, gin.H{
		"status":  200,
		"message": "Logged out",
	})
}
