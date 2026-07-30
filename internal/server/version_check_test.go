package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchLatestDockerTagFollowsPagination(t *testing.T) {
	requests := 0
	var registry *httptest.Server
	registry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		page := map[string]any{
			"next": "",
			"results": []map[string]string{
				{"name": "v2.20.2"},
				{"name": "latest"},
			},
		}
		if r.URL.Query().Get("page") == "" {
			page["next"] = registry.URL + "?page=2"
			page["results"] = []map[string]string{
				{"name": "v2.9.233"},
				{"name": "stable"},
			}
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer registry.Close()

	got, err := fetchLatestDockerTagFrom(context.Background(), registry.Client(), registry.URL)
	if err != nil {
		t.Fatal(err)
	}
	if got != "v2.20.2" {
		t.Fatalf("latest tag = %q, want v2.20.2", got)
	}
	if requests != 2 {
		t.Fatalf("registry requests = %d, want 2 pages", requests)
	}
}

func TestFetchLatestDockerTagRejectsRegistryError(t *testing.T) {
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer registry.Close()

	if _, err := fetchLatestDockerTagFrom(context.Background(), registry.Client(), registry.URL); err == nil {
		t.Fatal("expected non-200 registry response to return an error")
	}
}
