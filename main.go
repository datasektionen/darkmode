package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

type service struct {
	rdb              *redis.Client
	loginFrontendURL string
	loginAPIURL      string
	loginAPIKey      string
	plsURL           string
	webhookURLs      []string
	t                *template.Template
}

func main() {
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		panic(err)
	}

	url, err := url.Parse(os.Getenv("REDIS_URL"))
	if err != nil {
		panic(fmt.Errorf("Invalid REDIS_URL: %w", err))
	}
	redisPassword, ok := url.User.Password()
	if !ok {
		panic(fmt.Errorf("Invalid REDIS_URL: no password supplied"))
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:     url.Host,
		Password: redisPassword,
	})

	tmpl, err := template.ParseFS(templatesFS, "**/*")
	if err != nil {
		panic(fmt.Errorf("Could not parse templates: %w", err))
	}

	s := service{
		rdb:              rdb,
		loginFrontendURL: os.Getenv("LOGIN_FRONTEND_URL"),
		loginAPIURL:      os.Getenv("LOGIN_API_URL"),
		loginAPIKey:      os.Getenv("LOGIN_API_KEY"),
		plsURL:           os.Getenv("PLS_URL"),
		t:                tmpl,
	}

	for _, url := range strings.Split(os.Getenv("WEBHOOKS"), ",") {
		if url != "" {
			s.webhookURLs = append(s.webhookURLs, url)
		}
	}

	http.HandleFunc("GET /admin", s.adminPage)
	http.HandleFunc("POST /", s.setDarkmode)
	http.HandleFunc("GET /{$}", s.api)
	http.Handle("GET /static/", http.FileServerFS(staticFS))

	go func() {
		time.Sleep(time.Second * 5)
		s.sendWebhooks()
	}()

	if err := rdb.SetNX(context.Background(), "darkmode", true, 0).Err(); err != nil {
		slog.Error("Could not set default value for darkmode", "error", err)
		panic(err)
	}
	darkmode, err := rdb.Get(context.Background(), "darkmode").Bool()
	if err != nil {
		slog.Error("Could not get darkmode", "error", err)
		panic(err)
	}

	address := fmt.Sprintf(":%d", port)
	slog.Info("Darkmode started", "address", address, "darkmode", darkmode)
	http.ListenAndServe(address, nil)
}

func (s *service) sendWebhooks() {
	slog.Info("Sending webhooks", "count", len(s.webhookURLs))
	for _, url := range s.webhookURLs {
		if url == "" {
			continue
		}
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			slog.Error("Could not create request", "url", url, "error", err)
			continue
		}
		req.Header.Add("X-Darkmode-Event", "updated")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			slog.Error("Could not send request", "url", url, "error", err)
			continue
		}
		if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
			slog.Error("Webhook returned unexpected result", "url", url, "status", res.Status, "status-code", res.StatusCode)
			continue
		}
	}
}

func (s *service) api(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")

	darkmode, err := s.rdb.Get(r.Context(), "darkmode").Bool()
	if err != nil {
		slog.Error("Could not get darkmode", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	_, err = fmt.Fprint(w, darkmode)
	if err != nil {
		slog.Error("What?", "error", err)
	}
}

func (s *service) adminPage(w http.ResponseWriter, r *http.Request) {
	if code := r.FormValue("code"); code != "" {
		res, err := http.Get(s.loginAPIURL + "/verify/" + url.PathEscape(code) + "?api_key=" + s.loginAPIKey)
		if err != nil {
			slog.Error("Could not send request to login", "url", s.loginAPIURL, "error", err)
			http.Error(w, "Could not contact login", http.StatusInternalServerError)
			return
		}
		if res.StatusCode != http.StatusOK {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		var body struct {
			User string `user:"user"`
		}
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			slog.Error("Could not parse request from login system", "url", s.loginAPIURL, "error", err)
			http.Error(w, "Could not communicate with login system", http.StatusInternalServerError)
			return
		}
		res, err = http.Get(s.plsURL + "/api/user/" + url.PathEscape(body.User) + "/darkmode/switch")
		if err != nil {
			slog.Error("Could not send request to pls", "url", s.plsURL, "error", err)
			http.Error(w, "Could not contact pls", http.StatusInternalServerError)
			return
		}
		if res.StatusCode != http.StatusOK {
			http.Error(w, "Could not get permission status from pls", http.StatusInternalServerError)
			return
		}
		var hasPerm bool
		if err := json.NewDecoder(res.Body).Decode(&hasPerm); err != nil {
			slog.Error("Could not parse request from pls", "url", s.plsURL, "error", err)
			http.Error(w, "Could not communicate with pls", http.StatusInternalServerError)
			return
		}
		if !hasPerm {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		id := uuid.NewString()
		if err := s.rdb.SetEx(r.Context(), "session:"+id, body.User, time.Hour).Err(); err != nil {
			slog.Error("Could not save session in redis", "error", err)
			http.Error(w, "Could not save session", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: id})
		http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
		return
	}
	username, err := s.getSession(r)
	if err != nil {
		slog.Error("Could not get session", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if username == "" {
		scheme := "http"
		if fwProto := r.Header.Get("X-Forwarded-Proto"); fwProto != "" {
			scheme = fwProto
		}
		host := r.Host
		http.Redirect(w, r, s.loginFrontendURL+"/login?callback="+url.QueryEscape(scheme+"://"+host+"/admin?code="), http.StatusSeeOther)
		return
	}

	darkmode, err := s.rdb.Get(r.Context(), "darkmode").Bool()
	if err != nil {
		slog.Error("Could not get darkmode", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	if err := s.t.ExecuteTemplate(w, "admin.html", map[string]any{"username": username, "darkmode": darkmode}); err != nil {
		slog.Error("Could not render template", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (s *service) setDarkmode(w http.ResponseWriter, r *http.Request) {
	darkmodeString := r.FormValue("darkmode")
	var darkmode bool
	if err := json.Unmarshal([]byte(darkmodeString), &darkmode); err != nil {
		http.Error(w, "Invalid boolean", http.StatusBadRequest)
		return
	}
	username, err := s.getSession(r)
	if err != nil {
		slog.Error("Could not get session", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	slog.Info("Setting darkmode", "value", darkmode, "username", username)
	if err := s.rdb.Set(r.Context(), "darkmode", darkmode, 0).Err(); err != nil {
		slog.Error("Could not get darkmode", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	s.sendWebhooks()

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *service) getSession(r *http.Request) (string, error) {
	sessionCookie, _ := r.Cookie("session")
	if sessionCookie == nil {
		return "", nil
	}
	username, err := s.rdb.GetEx(r.Context(), "session:"+sessionCookie.Value, time.Hour).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("Could not get session from redis: %w", err)
	}
	return username, nil
}
