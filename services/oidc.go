package services

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	OidcConfig *oauth2.Config
	Verifier   *oidc.IDTokenVerifier
)

type ProviderMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func GetInsecureClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // ⛔ Do NOT use in production
			},
		},
	}
}

func SetupOIDC() error {
	providerURL := os.Getenv("OIDC_PROVIDER_URL")
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	redirectURL := os.Getenv("OIDC_REDIRECT_URL")

	ctx := context.Background()
	client := GetInsecureClient()

	// 1. Manually fetch metadata
	resp, err := client.Get(providerURL)
	if err != nil {
		return fmt.Errorf("failed to fetch OIDC metadata: %w", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var metadata ProviderMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return fmt.Errorf("invalid metadata format: %w", err)
	}

	// 2. Configure oauth2
	OidcConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  metadata.AuthorizationEndpoint,
			TokenURL: metadata.TokenEndpoint,
		},
		Scopes: []string{"openid", "profile", "email"},
	}

	// ✅ 3. Set up ID token verifier with trusted HTTP client
	ctx = oidc.ClientContext(ctx, client)
	keySet := oidc.NewRemoteKeySet(ctx, metadata.JWKSURI)
	Verifier = oidc.NewVerifier(metadata.Issuer, keySet, &oidc.Config{
		ClientID: clientID,
	})

	log.Println("✅ OIDC setup completed with ISVA manual metadata")
	return nil
}
