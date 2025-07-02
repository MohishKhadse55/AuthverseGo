package main

import (
	"authverseGo/routes"
	"authverseGo/services"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
}

func main() {

	server := gin.Default()
	server.LoadHTMLGlob("templates/*.html")

	// Setup OIDC
	if err := services.SetupOIDC(); err != nil {
		log.Fatalf("OIDC setup failed: %v", err)
	}

	// Setup SAML middleware
	samlSP, err := services.SetupSamlService()
	if err != nil {
		log.Fatalf("SAML setup failed: %v", err)
	}

	// // Optional: after SAML login, set session cookie and redirect
	// server.GET("/saml/callback", func(c *gin.Context) {
	// 	session, err := samlSP.Session.GetSession(c.Request)
	// 	if err != nil {
	// 		c.Redirect(http.StatusFound, "/api/v1/login")
	// 		return
	// 	}

	// 	// Type assert to access claims
	// 	claims, ok := session.(samlsp.JWTSessionClaims)
	// 	if !ok {
	// 		c.Redirect(http.StatusFound, "/api/v1/login")
	// 		return
	// 	}

	// 	// Example: get email from attributes
	// 	username := claims.Attributes.Get("email")
	// 	// or "NameID", etc.
	// 	if username == "" {
	// 		username = claims.Subject // fallback to subject
	// 	}

	// 	c.SetCookie("session_user", username, 3600, "/", "", false, true)
	// 	c.Redirect(http.StatusFound, "/api/v1/home")
	// })

	routes.RegisterRoutes(server, samlSP)
	server.Run(":8080")

}
