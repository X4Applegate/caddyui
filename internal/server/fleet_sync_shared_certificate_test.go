// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/X4Applegate/caddyui/internal/dns"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/X4Applegate/caddyui/web"
)

// v2.55.0 (issue #115): "source push" fleet distribution for a Managed ACME
// certificate — one server performs the ACME order, CaddyUI pushes the
// resulting certificate and private key to the selected targets instead of
// each of them running independent ACME. writeStorageCertificate (defined in
// certificate_export_test.go) lays out a certificate the way certmagic does,
// so these tests exercise the exact same on-disk read path as the v2.42.0
// "export to a directory" feature.

// newSourcePushCertificate creates a Managed ACME certificate on
// sourceServerID with "source push" fleet distribution opted in for
// targetServerIDs — as if the certificate form were saved with the new
// toggle and those "Also configure on" boxes checked.
func newSourcePushCertificate(t *testing.T, s *Server, sourceServerID int64, domains string, targetServerIDs ...int64) models.Certificate {
	t.Helper()
	parts := make([]string, len(targetServerIDs))
	for i, id := range targetServerIDs {
		parts[i] = strconv.FormatInt(id, 10)
	}
	cert := models.Certificate{
		// No DNSProfileID: dnsCredsFor only falls back to the legacy global
		// per-provider settings (settingCFAPIToken etc.) when the profile ID
		// is empty — see TestSourcePushCertificateCopiesCertAndKeyWithNoAutomationPolicyOnTarget.
		Name: "shared-wildcard", Domains: domains, Source: models.CertSourceManaged,
		DNSProvider:           "cloudflare",
		FleetDistributionMode: models.CertFleetDistributionSourcePush,
		FleetPushTargets:      strings.Join(parts, ","),
	}
	id, err := models.CreateCertificate(s.DB, sourceServerID, 0, &cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.ID = id
	return cert
}

// A source-push certificate is pushed to its target as a plain PEM copy
// (certificate and private key, read straight out of the source's Caddy
// storage) — no DNS credentials and no fleet-distribution fields of its own.
// The source keeps its own automation-policy entry (it still performs the
// ACME order); the target gets none at all, because
// buildDNSAutomationPolicies only emits one for Source == CertSourceManaged
// and the pushed copy is Source == CertSourcePEM.
func TestSourcePushCertificateCopiesCertAndKeyWithNoAutomationPolicyOnTarget(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "caddy", "certificates")
	serial := writeStorageCertificate(t, root, "acme-v02.api.letsencrypt.org-directory", "*.example.com", time.Now().Add(80*24*time.Hour))
	srv, _ := models.GetCaddyServer(s.DB, sourceServerID)
	srv.DataDir = dataDir
	if err := models.UpdateCaddyServer(s.DB, srv); err != nil {
		t.Fatal(err)
	}
	// So the source's own automation-policy assertion below reflects a real
	// policy rather than "credentials missing".
	if err := models.SetSetting(s.DB, settingCFAPIToken, "test-token"); err != nil {
		t.Fatal(err)
	}

	cert := newSourcePushCertificate(t, s, sourceServerID, "*.example.com", targetServerID)
	s.crossDeployCertificate("admin@example.com", sourceServerID, cert, cert.FleetPushTargetIDs())

	targets, err := models.ListCertificates(s.DB, targetServerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("target certificates = %#v, want exactly one pushed copy", targets)
	}
	got := targets[0]
	if got.Source != models.CertSourcePEM {
		t.Fatalf("target source = %q, want pem — the target must never run its own ACME", got.Source)
	}
	if got.DNSProvider != "" || got.DNSProfileID != "" {
		t.Fatalf("target DNS credentials = %q/%q, want empty — it must not be able to order its own certificate", got.DNSProvider, got.DNSProfileID)
	}
	if got.FleetDistributionMode != "" || got.FleetPushTargets != "" {
		t.Fatalf("pushed copy fleet-distribution fields = %q/%q, want empty", got.FleetDistributionMode, got.FleetPushTargets)
	}
	leaf := parsePEMLeaf(got.CertPEM)
	if leaf == nil || leaf.SerialNumber.Text(16) != serial {
		t.Fatalf("pushed certificate = %v, want serial %s", leaf, serial)
	}
	if !strings.Contains(got.KeyPEM, "PRIVATE KEY") {
		t.Fatalf("pushed private key missing: %q", got.KeyPEM)
	}

	// Requirement: only the source gets an automation-policy entry.
	sourcePolicies := s.buildDNSAutomationPolicies(nil, nil, nil, []models.Certificate{cert})
	if len(sourcePolicies) != 1 {
		t.Fatalf("source automation policies = %#v, want exactly one — it still performs the ACME order", sourcePolicies)
	}
	targetPolicies := s.buildDNSAutomationPolicies(nil, nil, nil, targets)
	if len(targetPolicies) != 0 {
		t.Fatalf("target automation policies = %#v, want none — it must never attempt its own ACME order", targetPolicies)
	}
}

// Before the source has completed its own ACME order — no Data directory
// configured yet, or a Data directory with nothing in storage yet — the push
// must not crash and must not create or overwrite the target with an empty
// or invalid certificate. It is skipped so the next certificate lifecycle
// reconciler pass can retry.
func TestSourcePushCertificateSkipsGracefullyBeforeSourceHasIssued(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	cert := newSourcePushCertificate(t, s, sourceServerID, "*.example.com", targetServerID)

	// No Data directory configured at all.
	if _, _, err := s.upsertFleetCertificate(sourceServerID, targetServerID, cert, 0); err == nil {
		t.Fatal("expected an error when the source has no Data directory configured")
	} else if !strings.Contains(err.Error(), "Data directory") {
		t.Fatalf("error = %v, want it to explain the missing Data directory", err)
	}
	if targets, _ := models.ListCertificates(s.DB, targetServerID); len(targets) != 0 {
		t.Fatalf("target certificates = %#v, want none created from a failed push", targets)
	}

	// Data directory configured, but Caddy has not stored a certificate yet.
	dataDir := t.TempDir()
	srv, _ := models.GetCaddyServer(s.DB, sourceServerID)
	srv.DataDir = dataDir
	if err := models.UpdateCaddyServer(s.DB, srv); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.upsertFleetCertificate(sourceServerID, targetServerID, cert, 0); err == nil {
		t.Fatal("expected an error when the source hasn't completed its own ACME order yet")
	} else if !strings.Contains(err.Error(), "has not completed its own ACME order") {
		t.Fatalf("error = %v, want it to explain the missing certificate", err)
	}
	if targets, _ := models.ListCertificates(s.DB, targetServerID); len(targets) != 0 {
		t.Fatalf("target certificates = %#v, want none created from a failed push", targets)
	}

	// Once the source has actually issued, the next attempt (simulating the
	// reconciler's next pass) succeeds.
	writeStorageCertificate(t, filepath.Join(dataDir, "caddy", "certificates"), "acme-v02.api.letsencrypt.org-directory", "*.example.com", time.Now().Add(80*24*time.Hour))
	result, byPath, err := s.upsertFleetCertificate(sourceServerID, targetServerID, cert, 0)
	if err != nil || byPath || !result.Created {
		t.Fatalf("retry after issuance = %#v, byPath %v, err %v; want a fresh copy created", result, byPath, err)
	}
}

// pushSharedManagedCertificates (the certificate lifecycle reconciler's hook)
// picks up a renewal on the source without the certificate form being saved
// again, lands it on the same target row, and leaves an unrelated
// default-mode managed certificate on the same source completely untouched.
func TestPushSharedManagedCertificatesPicksUpRenewalAndLeavesIndependentCertsAlone(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	dataDir := t.TempDir()
	root := filepath.Join(dataDir, "caddy", "certificates")
	writeStorageCertificate(t, root, "acme-v02.api.letsencrypt.org-directory", "*.example.com", time.Now().Add(80*24*time.Hour))
	srv, _ := models.GetCaddyServer(s.DB, sourceServerID)
	srv.DataDir = dataDir
	if err := models.UpdateCaddyServer(s.DB, srv); err != nil {
		t.Fatal(err)
	}
	newSourcePushCertificate(t, s, sourceServerID, "*.example.com", targetServerID)

	// An unrelated, default-mode managed certificate on the same source must
	// never be touched by the reconciler hook (zero behavior change).
	independent := models.Certificate{Name: "independent", Domains: "independent.example.com", Source: models.CertSourceManaged, DNSProvider: "cloudflare", DNSProfileID: "p"}
	if _, err := models.CreateCertificate(s.DB, sourceServerID, 0, &independent); err != nil {
		t.Fatal(err)
	}

	if attempted, err := s.pushSharedManagedCertificates(); err != nil || attempted != 1 {
		t.Fatalf("pushSharedManagedCertificates = %d, %v; want exactly one source-push certificate attempted", attempted, err)
	}
	targets, _ := models.ListCertificates(s.DB, targetServerID)
	if len(targets) != 1 {
		t.Fatalf("target certificates = %#v, want exactly one pushed copy", targets)
	}
	firstLeaf := parsePEMLeaf(targets[0].CertPEM)
	if firstLeaf == nil {
		t.Fatalf("pushed certificate did not parse: %+v", targets[0])
	}
	firstSerial := firstLeaf.SerialNumber.Text(16)
	targetCertID := targets[0].ID

	// Simulate a renewal landing in the source's storage (same issuer
	// directory, so it overwrites in place exactly as certmagic would).
	renewedSerial := writeStorageCertificate(t, root, "acme-v02.api.letsencrypt.org-directory", "*.example.com", time.Now().Add(90*24*time.Hour))
	if renewedSerial == firstSerial {
		t.Fatal("test fixture produced the same serial twice")
	}
	if attempted, err := s.pushSharedManagedCertificates(); err != nil || attempted != 1 {
		t.Fatalf("renewal pass = %d, %v", attempted, err)
	}
	targets, _ = models.ListCertificates(s.DB, targetServerID)
	if len(targets) != 1 || targets[0].ID != targetCertID {
		t.Fatalf("renewal should land on the same target row: %+v", targets)
	}
	if leaf := parsePEMLeaf(targets[0].CertPEM); leaf == nil || leaf.SerialNumber.Text(16) != renewedSerial {
		t.Fatalf("target certificate = %v, want the renewed serial %s", leaf, renewedSerial)
	}

	// A third, unchanged pass touches nothing further (idempotent).
	if attempted, err := s.pushSharedManagedCertificates(); err != nil || attempted != 1 {
		t.Fatalf("steady-state pass = %d, %v", attempted, err)
	}
	targets, _ = models.ListCertificates(s.DB, targetServerID)
	if len(targets) != 1 || targets[0].ID != targetCertID {
		t.Fatalf("steady-state pass should not duplicate or move the target row: %+v", targets)
	}

	// The independent-mode certificate never got a target row at all.
	for _, c := range targets {
		if c.Domains == "independent.example.com" {
			t.Fatalf("independent-mode certificate must not be cross-deployed by the reconciler hook: %+v", c)
		}
	}
}

// Without opting into source-push mode, cross-deploying a Managed ACME
// certificate is completely unchanged from pre-v2.55.0 behavior: the target
// gets its own DNS-01 definition (same DNS credentials) and orders its own
// certificate — no PEM material travels, and the target still gets its own
// automation-policy entry.
func TestCrossDeployManagedCertificateDefaultModeStillClonesDNSDefinitionOnly(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	for key, value := range map[string]string{
		settingRoute53AccessKeyID:     "AKIAEXAMPLE",
		settingRoute53SecretAccessKey: "secret",
	} {
		if err := models.SetSetting(s.DB, key, value); err != nil {
			t.Fatal(err)
		}
	}
	cert := models.Certificate{Name: "wildcard", Domains: "*.example.com", Source: models.CertSourceManaged, DNSProvider: dns.Route53}
	id, err := models.CreateCertificate(s.DB, sourceServerID, 0, &cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.ID = id
	if cert.FleetDistributionMode != "" {
		t.Fatalf("default FleetDistributionMode = %q, want empty", cert.FleetDistributionMode)
	}

	s.crossDeployCertificate("admin@example.com", sourceServerID, cert, []int64{targetServerID})

	targets, _ := models.ListCertificates(s.DB, targetServerID)
	if len(targets) != 1 {
		t.Fatalf("target certificates = %#v, want exactly one cloned definition", targets)
	}
	got := targets[0]
	if got.Source != models.CertSourceManaged {
		t.Fatalf("target source = %q, want managed — default mode orders its own certificate", got.Source)
	}
	if got.DNSProvider != dns.Route53 {
		t.Fatalf("target DNS provider = %q, want cloned from source", got.DNSProvider)
	}
	if got.CertPEM != "" || got.KeyPEM != "" {
		t.Fatalf("target certificate/key = %q/%q, want empty — no PEM material travels in the default mode", got.CertPEM, got.KeyPEM)
	}

	// The target also gets its own automation-policy entry, exactly as before.
	policies := s.buildDNSAutomationPolicies(nil, nil, nil, targets)
	if len(policies) != 1 {
		t.Fatalf("target automation policies = %#v, want exactly one — it must still run its own ACME", policies)
	}
}

// fleetCertificateMatches must treat a source-push certificate's eventual
// copy as non-managed (it will be a PEM copy — see sourcePushCertificateCopy)
// while leaving the default-mode comparison exactly as it was.
func TestFleetCertificateMatchesSourcePushTreatsCopyAsNonManaged(t *testing.T) {
	managedSource := models.Certificate{Domains: "*.example.com", Source: models.CertSourceManaged}
	pushSource := models.Certificate{Domains: "*.example.com", Source: models.CertSourceManaged, FleetDistributionMode: models.CertFleetDistributionSourcePush}
	managedTarget := models.Certificate{Domains: "*.example.com", Source: models.CertSourceManaged}
	pemTarget := models.Certificate{Domains: "*.example.com", Source: models.CertSourcePEM}

	if !fleetCertificateMatches(managedTarget, managedSource) {
		t.Error("default mode: a managed target should match a managed source (unchanged pre-v2.55.0 behavior)")
	}
	if fleetCertificateMatches(pemTarget, managedSource) {
		t.Error("default mode: a PEM target should not match a managed source (unchanged pre-v2.55.0 behavior)")
	}
	if fleetCertificateMatches(managedTarget, pushSource) {
		t.Error("source-push mode: a managed target should not match a push-mode source — the copy it produces is PEM, not managed")
	}
	if !fleetCertificateMatches(pemTarget, pushSource) {
		t.Error("source-push mode: a PEM target should match a push-mode source — that is what the copy actually is")
	}
}

// certificate_form.html's new Go-template syntax (index on FleetPushTargetSet,
// the fleet_distribution_mode checkbox) is otherwise never exercised by the
// test suite — nothing calls server.New with the real embedded templates, so
// a runtime template error here (as opposed to a parse error, which would
// already fail any such call) would only ever surface by a human clicking
// into the certificate edit page. This renders the real compiled template
// through the real render path for both a fresh form and an existing
// source-push certificate, and checks the toggle/target checkbox reflect
// FleetDistributionMode/FleetPushTargetSet correctly in the markup.
func TestCertificateFormTemplateRendersSourcePushToggle(t *testing.T) {
	s, sourceServerID, targetServerID := newFleetSyncTestServer(t)
	tplFS, err := fs.Sub(web.FS, "templates")
	if err != nil {
		t.Fatal(err)
	}
	real, err := New(s.DB, nil, tplFS, nil, "", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	target, err := models.GetCaddyServer(real.DB, targetServerID)
	if err != nil {
		t.Fatal(err)
	}

	cert := newSourcePushCertificate(t, real, sourceServerID, "*.example.com", targetServerID)

	render := func(c *models.Certificate) string {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/certificates/new", nil)
		real.render(rec, req, "certificate_form.html", map[string]any{
			"Cert":         c,
			"OtherServers": []models.CaddyServer{*target},
			"Section":      "certs",
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("render status = %d, body = %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	// Fresh form: the toggle markup must be present but unchecked, and the
	// target checkbox must not be pre-checked.
	fresh := render(&models.Certificate{Source: models.CertSourcePEM})
	if !strings.Contains(fresh, `name="fleet_distribution_mode"`) {
		t.Fatal("fresh form is missing the source-push toggle markup")
	}
	if strings.Contains(fresh, `name="fleet_distribution_mode" value="source_push" checked`) {
		t.Fatal("fresh form must not pre-check the source-push toggle")
	}
	wantUnchecked := fmt.Sprintf(`value="%d"  onchange`, targetServerID)
	if !strings.Contains(fresh, wantUnchecked) {
		t.Fatalf("fresh form should not pre-check target %d, body:\n%s", targetServerID, fresh)
	}

	// Editing the source-push certificate: both the toggle and its target
	// checkbox must render pre-checked.
	edited := render(&cert)
	if !strings.Contains(edited, `name="fleet_distribution_mode" value="source_push" checked`) {
		t.Fatalf("editing a source-push certificate should pre-check the toggle, body:\n%s", edited)
	}
	wantChecked := fmt.Sprintf(`value="%d" checked onchange`, targetServerID)
	if !strings.Contains(edited, wantChecked) {
		t.Fatalf("editing a source-push certificate should pre-check its target %q, body:\n%s", wantChecked, edited)
	}
}
