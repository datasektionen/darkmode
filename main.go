package main

import (
	"context"
	"embed"
	"encoding/json"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
	"github.com/coreos/go-oidc/v3/oidc"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

type Service struct {
	db               *pgxpool.Pool
	oauth2Config     oauth2.Config
	verifier         *oidc.IDTokenVerifier
	ctx              context.Context
	hiveURL          string
	hiveAPIKey       string
	webhookURLs      []string
	t                *template.Template
}

func main() {
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		panic("Invalid port: " + err.Error())
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		panic("Missing $DATABASE_URL")
	}
	db, err := pgxpool.New(context.Background(), dbURL)
	if _, err := db.Exec(context.Background(), `
        create table if not exists darkmode (
            unique_marker text primary key check (unique_marker = 'unique_marker') default 'unique_marker',
            darkmode boolean not null default true
        );
        insert into darkmode default values on conflict do nothing;

        create table if not exists sessions (
            id uuid primary key default gen_random_uuid(),
            last_used_at timestamp not null default now(),
            kthid text not null
        );
    `); err != nil {
		panic("Home-made migration failed: " + err.Error())
	}

	tmpl, err := template.ParseFS(templatesFS, "**/*")
	if err != nil {
		panic(fmt.Errorf("Could not parse templates: %w", err))
	}

	ctx := context.Background()
	oauth2Config, verifier := InitOIDC(ctx)

	s := Service{
		db:               db,
		oauth2Config:     oauth2Config,
		verifier:         verifier,
		ctx:              ctx,
		hiveURL:          os.Getenv("HIVE_URL"),
		hiveAPIKey:       os.Getenv("HIVE_API_KEY"),
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
	http.HandleFunc("/oidc/callback", HandleOAuth2)

	go func() {
		time.Sleep(time.Second * 5)
		s.sendWebhooks()
	}()

	var initDarkmode bool
	if err := db.QueryRow(context.Background(), `select darkmode from darkmode`).Scan(&initDarkmode); err != nil {
		slog.Error("Could not get darkmode", "error", err)
		panic(err)
	}

	address := fmt.Sprintf(":%d", port)
	slog.Info("Darkmode started", "address", address, "darkmode", initDarkmode)
	http.ListenAndServe(address, nil)
}

func (s *Service) sendWebhooks() {
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

func (s *Service) api(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")

	var darkmode bool
	if err := s.db.QueryRow(r.Context(), `select darkmode from darkmode`).Scan(&darkmode); err != nil {
		slog.Error("Could not get darkmode", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	if _, err := fmt.Fprint(w, darkmode); err != nil {
		slog.Error("What?", "error", err)
	}
}

func (s *Service) adminPage(w http.ResponseWriter, r *http.Request) {
	if code := r.FormValue("code"); code != "" {
		user, auth, err := Auth(w, r, s.oauth2Config)


		if !hasPerm {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		var id uuid.UUID
		if err := s.db.QueryRow(r.Context(), `insert into sessions (kthid) values ($1) returning id`, body.User).Scan(&id); err != nil {
			slog.Error("Could not save session in db", "error", err)
			http.Error(w, "Could not save session", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: id.String()})
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

	var darkmode bool
	if err := s.db.QueryRow(r.Context(), `select darkmode from darkmode`).Scan(&darkmode); err != nil {
		slog.Error("Could not get darkmode", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	if err := s.t.ExecuteTemplate(w, "admin.html", map[string]any{"username": username, "darkmode": darkmode}); err != nil {
		slog.Error("Could not render template", "error", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (s *Service) setDarkmode(w http.ResponseWriter, r *http.Request) {
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
	if tag, err := s.db.Exec(r.Context(), `update darkmode set darkmode = $1`, darkmode); err != nil || tag.RowsAffected() != 1 {
		slog.Error("Could not set darkmode", "error", err, "rows affected", tag.RowsAffected())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	s.sendWebhooks()

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Service) getSession(r *http.Request) (string, error) {
	sessionCookie, _ := r.Cookie("session")
	if sessionCookie == nil {
		return "", nil
	}
	if _, err := s.db.Exec(r.Context(), `
        delete from sessions
        where last_used_at < now() - interval '1 hour'
    `); err != nil {
		return "", fmt.Errorf("Could not clean up old sessions: %w", err)
	}

	var username string
	if err := s.db.QueryRow(r.Context(), `
        update sessions
        set last_used_at = now()
        where id = $1
        returning kthid
    `, sessionCookie.Value).Scan(&username); err == pgx.ErrNoRows {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("Could not get session from db: %w", err)
	}
	return username, nil
}
