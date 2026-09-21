// SPDX-License-Identifier: Apache-2.0

package server

import (
	"path/filepath"
	"testing"
	"time"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// TestAIRequestTimeout is the regression test for issue #109: the AI chat
// request deadline is configurable, defaults to 90s, and clamps out-of-range
// or garbage values instead of trusting them.
func TestAIRequestTimeout(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &Server{DB: conn}

	cases := []struct {
		name string
		set  string // "" means leave unset
		want time.Duration
	}{
		{"unset falls back to default", "", 90 * time.Second},
		{"custom value honoured", "600", 600 * time.Second},
		{"minimum honoured", "5", 5 * time.Second},
		{"maximum honoured", "3600", 3600 * time.Second},
		{"below minimum falls back to default", "2", 90 * time.Second},
		{"above maximum falls back to default", "99999", 90 * time.Second},
		{"garbage falls back to default", "soon", 90 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := models.SetSetting(conn, settingAIRequestTimeoutSec, tc.set); err != nil {
				t.Fatal(err)
			}
			if got := s.aiRequestTimeout(); got != tc.want {
				t.Errorf("aiRequestTimeout() = %v, want %v", got, tc.want)
			}
		})
	}
}
