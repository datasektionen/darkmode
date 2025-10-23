package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

func InitOIDC(ctx context.Context) (oauth2.Config, *oidc.IDTokenVerifier) {
	provider, err := oidc.NewProvider(ctx, os.Getenv("OIDC_PROVIDOR"))
	if err != nil {
		log.Panicln(err.Error())
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     os.Getenv("OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("OIDC_REDIRECT_URL"),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID},
	}
	var verifier = provider.Verifier(&oidc.Config{ClientID: os.Getenv("OIDC_CLIENT_ID")})

	return oauth2Config, verifier
}

func Auth(w http.ResponseWriter, r *http.Request, oauth2Config oauth2.Config) (string, int, error) {
	cookie, err := r.Cookie("session")

	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, oauth2Config.AuthCodeURL("test"), http.StatusFound)
		return "", 0, err
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("there's an error with the signing method")
		}
		return []byte(os.Getenv("APP_SECRET_KEY")), nil
	})

	if err != nil {
		panic(err.Error())
	}

	claims := token.Claims.(jwt.MapClaims)

	sub := claims["sub"].(string)
	auth := int(claims["auth"].(float64))

	return sub, auth, nil
}
