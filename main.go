package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		_, err := w.Write([]byte(darkmode))
		if err != nil {
			slog.Error("What?", "error", err)
		}
	})

	address := fmt.Sprintf(":%d", port)
	slog.Info("Darkmode started", "address", address, "darkmode", darkmode)
	http.ListenAndServe(address, nil)
}
