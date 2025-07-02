package controllers

import (
	"authverseGo/models"
	"authverseGo/services"
	"context"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/crewjam/saml/samlsp"
	"github.com/gin-gonic/gin"
)

const sessionCookie = "session_user"

func ShowLoginForm(c *gin.Context) {
	if _, err := c.Cookie(sessionCookie); err == nil {
		c.Redirect(http.StatusFound, "/api/v1/home")
		return
	}
	c.HTML(http.StatusOK, "login.html", gin.H{"error": ""})
}

func Login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	if valid := models.ValidateUser(username, password); valid {
		c.SetCookie(sessionCookie, username, 3600, "/", "", false, true)
		c.Redirect(http.StatusFound, "/api/v1/home")
	} else {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Invalid  credentials"})
	}

}

func Home(c *gin.Context) {
	username, err := c.Cookie(sessionCookie)
	if err != nil {
		c.Redirect(http.StatusFound, "/api/v1/login")
		return
	}
	c.HTML(http.StatusOK, "home.html", gin.H{"username": username})
}

func Logout(c *gin.Context) {
	c.SetCookie(sessionCookie, "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/api/v1/login")
}

func SamlLoginHandler(samlSP *samlsp.Middleware) http.Handler {
	return samlSP.RequireAccount(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure there is a SAML session
		sess := samlsp.SessionFromContext(r.Context())
		if sess == nil {
			http.Error(w, "SAML session missing", http.StatusUnauthorized)
			return
		}

		// 2) Assert to SessionWithAttributes
		sai, ok := sess.(samlsp.SessionWithAttributes)
		if !ok {
			http.Error(w, "session has no attributes", http.StatusInternalServerError)
			return
		}

		// 3) Pull out the saml.Attributes
		attrs := sai.GetAttributes()

		// 4) Loop and print

		fmt.Printf("All attributes: %#v\n", attrs)

		// Get the "email" attribute from the session (IdP must include it)

		user := samlsp.AttributeFromContext(r.Context(), "emailAddress")
		if user == "" {
			http.Error(w, "Email attribute not found in SAML assertion", http.StatusUnauthorized)
			return
		}

		// Set your app’s session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_user",
			Value:    user,
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
		})

		// Redirect into your existing home page
		http.Redirect(w, r, "/api/v1/home", http.StatusFound)
	}))
}

func OIDCLogin(c *gin.Context) {
	authURL := services.OidcConfig.AuthCodeURL("state-xyz")
	c.Redirect(http.StatusFound, authURL)
}

func OIDCCallback(c *gin.Context) {
	if c.Query("state") != "state-xyz" {
		c.String(http.StatusBadRequest, "Invalid state")
		return
	}

	ctx := context.Background()
	code := c.Query("code")

	// Use custom HTTP client to trust ISVA certificate
	token, err := services.OidcConfig.Exchange(
		oidc.ClientContext(ctx, services.GetInsecureClient()),
		code,
	)
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("Token exchange failed: %v", err))
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.String(http.StatusInternalServerError, "Missing id_token")
		return
	}

	idToken, err := services.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("ID token verify failed: %v", err))
		return
	}

	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("Parse claims failed: %v", err))
		return
	}

	// Set session or cookie
	c.SetCookie("session_user", claims.Email, 3600, "/", "", false, true)
	c.Redirect(http.StatusFound, "/api/v1/home")
}
