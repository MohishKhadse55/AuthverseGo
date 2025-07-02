package routes

import (
	"authverseGo/controllers"
	"authverseGo/middleware"

	"github.com/crewjam/saml/samlsp"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(server *gin.Engine, samlSP *samlsp.Middleware) {
	v1 := server.Group("/api/v1")
	{
		v1.GET("/login", controllers.ShowLoginForm)
		v1.POST("/login", controllers.Login)

		v1.GET("/home", middleware.AuthRequired, controllers.Home)
		v1.GET("/logout", middleware.AuthRequired, controllers.Logout)
		v1.GET("/saml/login", gin.WrapH(controllers.SamlLoginHandler(samlSP)))
		v1.GET("/oidc/login", controllers.OIDCLogin)
		v1.GET("/oidc/callback", controllers.OIDCCallback)

	}

	server.Any("saml/*any", gin.WrapH(samlSP))
}
