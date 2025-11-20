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
		Scopes: []string{oidc.ScopeOpenID, "permissions"},
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
	auth := int(claims["permissions"].(float64))

	return sub, auth, nil
}

func (s *Service) HandleOAuth2(w http.ResponseWriter, r *http.Request) {
	// Verify state and errors.
	oauth2Token, err := s.oauth2Config.Exchange(s.ctx, r.URL.Query().Get("code"))
	if err != nil {
		panic(err.Error())
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		panic("No id token")
	}

	// Parse and verify ID Token payload.
	idToken, err := s.verifier.Verify(s.ctx, rawIDToken)
	if err != nil {
		panic(err.Error())
	}

	// Get permissions from HIVE
	url := fmt.Sprintf("%s/user/%s/permissions", os.Getenv("HIVE_API_URL"), idToken.Subject)

	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + os.Getenv("HIVE_API_KEY")

	// Create a new request using http
	req, err := http.NewRequest("GET", url, nil)

	// add authorization header to the req
	req.Header.Add("Authorization", bearer)

	// Send req using http Client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error on response.\n[ERROR] -", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error while reading the response bytes:", err)
	}
	var perm []Permission
	json.Unmarshal(body, &perm)

	var permission int
	var permString string

	for i := range perm {
		if perm[i].Id == "manager" {
			permission = ADMIN
			permString = "manager"
		}

		if perm[i].Id == "user" && permission != ADMIN {
			permission = USER
			permString = "user"
		}
	}

	key := []byte(os.Getenv("APP_SECRET_KEY"))
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["iss"] = "pax"
	claims["sub"] = idToken.Subject
	claims["auth"] = permission

	signedToken, err := token.SignedString(key)

	if err != nil {
		panic(err.Error())
	}

	cookie := http.Cookie{
		Name:     "session",
		Value:    signedToken,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	log.Printf("user %s logged in with permission %s", idToken.Subject, permString)

	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusFound)
}
