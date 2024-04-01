package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		panic(err)
	}

	darkmode := os.Getenv("DARKMODE")
	if darkmode != "false" {
		darkmode = "true"
	}

	http.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")

		_, err := w.Write([]byte(darkmode))
		if err != nil {
			slog.Error("What?", "error", err)
		}
	})

	go func() {
		time.Sleep(time.Second * 5)
		sendWebhooks()
	}()

	address := fmt.Sprintf(":%d", port)
	slog.Info("Darkmode started", "address", address, "darkmode", darkmode)
	http.ListenAndServe(address, nil)
}

var webhookURLs []string

func init() {
	for _, url := range strings.Split(os.Getenv("WEBHOOKS"), ",") {
		if url != "" {
			webhookURLs = append(webhookURLs, url)
		}
	}
}

func sendWebhooks() {
	slog.Info("Sending webhooks", "count", len(webhookURLs))
	for _, url := range webhookURLs {
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
