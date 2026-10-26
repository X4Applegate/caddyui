// SPDX-License-Identifier: Apache-2.0

package caddylogs

import (
	"path/filepath"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #151: a failed ACME renewal-information (ARI) update left the
// certificate stuck on "Issuance error" forever. Caddy recovers by logging a
// successful ARI update, which issues no certificate and therefore emits no
// cert_obtained event, so nothing cleared the stored failure.
func TestHubClearsErrorAfterSuccessfulRenewalInfoUpdate(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	hub := New(conn)
	// The reporter's failure: a transient DNS outage while updating ARI.
	hub.AcceptLine([]byte(`{"level":"error","ts":1760000000,"logger":"tls.cache.maintenance","msg":"failed updating renewal info from ACME CA","identifiers":["*.example.com"],"error":"provisioning client: performing request: Get \"https://acme-v02.api.letsencrypt.org/directory\": dial tcp: lookup acme-v02.api.letsencrypt.org on 127.0.0.11:53: server misbehaving","caddyui_server_id":3,"caddyui_server_name":"edge"}`))
	states, err := models.ListCertificateLifecycle(conn, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "error" || states[0].Identifier != "*.example.com" {
		t.Fatalf("ARI failure state = %#v, want error for *.example.com", states)
	}

	// Two weeks later Caddy updates the renewal information successfully. The
	// certificate is valid and served, so the stored error must clear.
	hub.AcceptLine([]byte(`{"level":"info","ts":1761400000,"logger":"tls.cache.maintenance","msg":"updated and stored ACME renewal information","identifiers":["*.example.com"],"caddyui_server_id":3,"caddyui_server_name":"edge"}`))
	states, err = models.ListCertificateLifecycle(conn, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 {
		t.Fatalf("lifecycle rows = %#v, want one compact row", states)
	}
	if states[0].Phase != "active" {
		t.Fatalf("phase after successful ARI update = %q, want active", states[0].Phase)
	}
	if states[0].Error != "" {
		t.Fatalf("stale issuance error survived recovery: %q", states[0].Error)
	}
}

// A scheduled ARI refresh is routine maintenance on a healthy certificate. It
// must not be reported to the operator as an in-flight renewal.
func TestHubDoesNotTreatRenewalInfoCheckAsRenewing(t *testing.T) {
	conn, err := appdb.Open(filepath.Join(t.TempDir(), "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	hub := New(conn)
	hub.AcceptLine([]byte(`{"level":"info","ts":1761400001,"logger":"tls.cache.maintenance","msg":"certificate expires soon; renewing","identifiers":["renew.example"],"caddyui_server_id":4,"caddyui_server_name":"edge"}`))
	states, err := models.ListCertificateLifecycle(conn, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Phase != "renewing" {
		t.Fatalf("renewal state = %#v, want renewing", states)
	}
}
