package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const sessionCookie = "session_user"

func AuthRequired(c *gin.Context) {
	if _, err := c.Cookie(sessionCookie); err != nil {
		// Not logged in
		c.Redirect(http.StatusFound, "/api/v1/login")
		c.Abort()
		return
	}
	c.Next()
}
