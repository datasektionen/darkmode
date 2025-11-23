package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type Permission struct {
	Id    string
	Scope string
}

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
		Scopes: []string{oidc.ScopeOpenID, "permissions"},
	}
	var verifier = provider.Verifier(&oidc.Config{ClientID: os.Getenv("OIDC_CLIENT_ID")})

	return oauth2Config, verifier
}

func RandString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func SetCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func Auth(w http.ResponseWriter, r *http.Request, oauth2Config oauth2.Config) (string, bool, error) {
	cookie, err := r.Cookie("session")

	if err != nil || cookie.Value == "" {
		state, err := RandString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return "", false, err
		}
		SetCallbackCookie(w, r, "state", state)

		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
		return "", false, err
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("there's an error with the signing method")
		}
		return []byte(os.Getenv("APP_SECRET_KEY")), nil
	})

	if err != nil {
		http.Error(w, "jwt parse error", http.StatusBadRequest)
		return "", false, err
	}

	claims := token.Claims.(jwt.MapClaims)

	sub := claims["sub"].(string)
	auth := claims["auth"].(bool)

	return sub, auth, nil
}

func (s *Service) HandleOAuth2(w http.ResponseWriter, r *http.Request) {
	// Verify state and errors.
	state, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != state.Value {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	oauth2Token, err := s.oauth2Config.Exchange(s.ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "failed to exchange code", http.StatusBadRequest)
		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id token", http.StatusBadRequest)
		return
	}

	// Parse and verify ID Token payload.
	idToken, err := s.verifier.Verify(s.ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify id token", http.StatusBadRequest)
		return
	}

	var claims struct {
		Permissions []Permission `json:"permissions"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to extract claims", http.StatusBadRequest)
		return
	}

	permission := false

	for _, perm := range claims.Permissions {
		if perm.Id == "switch" {
			permission = true
		}
	}

	key := []byte(os.Getenv("APP_SECRET_KEY"))
	token := jwt.New(jwt.SigningMethodHS256)
	tokenClaims := token.Claims.(jwt.MapClaims)
	tokenClaims["iss"] = "darkmode"
	tokenClaims["sub"] = idToken.Subject
	tokenClaims["auth"] = permission

	signedToken, err := token.SignedString(key)

	if err != nil {
		http.Error(w, "Failed to sign jwt", http.StatusInternalServerError)
		return
	}

	slog.Info("Loging in user", "user", idToken.Subject, "admin", permission)

	cookie := http.Cookie{
		Name:     "session",
		Value:    signedToken,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/admin", http.StatusFound)
}
