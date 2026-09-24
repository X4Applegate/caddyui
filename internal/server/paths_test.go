// SPDX-License-Identifier: Apache-2.0

package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	appdb "github.com/X4Applegate/caddyui/internal/db"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Review finding #8 (2026-09-21): safeAbsolutePath blocks "../" but confines
// nothing, so an admin-configured certificate path could name any absolute
// file the process can read. confinedReadPath adds the containment.
func TestConfinedReadPathConfinesToRoots(t *testing.T) {
	roots := []string{"/certs", "/etc/caddy"}

	for _, good := range []string{
		"/certs/example.com/fullchain.pem",
		"/certs",
		"/etc/caddy/tls/site.crt",
		" /certs//example.com/./fullchain.pem ",
	} {
		if _, err := confinedReadPath(good, roots); err != nil {
			t.Errorf("%q should be allowed, got %v", good, err)
		}
	}

	for _, bad := range []string{
		"/etc/shadow",
		"/etc/passwd",
		"/data/caddyui.db",
		"/certs-other/x.pem", // prefix-adjacent, not inside /certs
		"/etc/caddyfile",     // ditto for a file sharing the root's prefix
		"/",
	} {
		err := mustRejectPath(t, bad, roots)
		if err != nil && !strings.Contains(err.Error(), "outside") {
			t.Errorf("%q: error should say the path is outside the roots, got %v", bad, err)
		}
	}
}

// The traversal and absolute-path rules from safeAbsolutePath still apply,
// and are reported as themselves rather than as a containment failure.
func TestConfinedReadPathKeepsSafeAbsolutePathRules(t *testing.T) {
	roots := []string{"/certs"}
	for _, bad := range []string{"", "certs/x.pem", "/certs/../etc/passwd", "relative/../x"} {
		if _, err := confinedReadPath(bad, roots); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// Fails closed: no roots, or only meaningless ones, means nothing is readable.
// A root of "/" would allow every path, so it is dropped rather than honored.
func TestConfinedReadPathFailsClosedWithoutUsableRoots(t *testing.T) {
	for _, roots := range [][]string{nil, {}, {"/"}, {"", "  ", "relative/dir", "/etc/../"}} {
		if _, err := confinedReadPath("/certs/x.pem", roots); err == nil {
			t.Errorf("roots %q must not allow any path", roots)
		}
	}
}

// A symlink planted inside an allowed root must not become a way out of it:
// both sides are resolved before they are compared, and the resolved path is
// what the caller opens, so there is no gap between the check and the read.
func TestConfinedReadPathResolvesSymlinkEscapes(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "certs")
	outside := filepath.Join(base, "secrets")
	for _, dir := range []string{root, outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(outside, "shadow")
	if err := os.WriteFile(secret, []byte("root:!:20000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "fullchain.pem")
	if err := os.WriteFile(real, []byte("-----BEGIN CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	escape := filepath.Join(root, "escape.pem")
	if err := os.Symlink(secret, escape); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := confinedReadPath(escape, []string{root}); err == nil {
		t.Error("a symlink out of the root must be refused")
	}
	if _, err := readCertificateFile(escape, []string{root}); err == nil {
		t.Error("readCertificateFile must refuse the symlink escape")
	}

	// A symlink that stays inside the root is fine, and so is a symlinked root.
	inside := filepath.Join(root, "link.pem")
	if err := os.Symlink(real, inside); err != nil {
		t.Fatal(err)
	}
	if _, err := readCertificateFile(inside, []string{root}); err != nil {
		t.Errorf("symlink within the root should be readable: %v", err)
	}
	linkedRoot := filepath.Join(base, "certs-link")
	if err := os.Symlink(root, linkedRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := readCertificateFile(real, []string{linkedRoot}); err != nil {
		t.Errorf("symlinked root should still contain its files: %v", err)
	}
}

// certificateReadRoots is what the handlers actually pass: CaddyUI's own data
// directory, every node's mounted Caddy data volume, the conventional
// locations, and the operator's additions — de-duplicated, "/" dropped.
func TestCertificateReadRoots(t *testing.T) {
	dir := t.TempDir()
	conn, err := appdb.Open(filepath.Join(dir, "caddyui.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := models.CreateCaddyServer(conn, &models.CaddyServer{
		Name: "Primary", AdminURL: "http://127.0.0.1:2019",
		Type: models.CaddyServerTypeManaged, DataDir: "/srv/caddy-data",
	}); err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: conn, DBPath: filepath.Join(dir, "caddyui.db")}

	roots := s.certificateReadRoots()
	has := func(want string) bool {
		for _, r := range roots {
			if r == want {
				return true
			}
		}
		return false
	}
	if !has(dir) {
		t.Errorf("CaddyUI's own data dir %q missing from %v", dir, roots)
	}
	if !has("/srv/caddy-data") {
		t.Errorf("node DataDir missing from %v", roots)
	}
	for _, def := range defaultCertificateReadRoots {
		if !has(def) {
			t.Errorf("default root %q missing from %v", def, roots)
		}
	}

	// Operator additions are honored; "/" and junk are not.
	if err := models.SetSetting(conn, settingCertificateReadRoots, "/opt/tls\n/mnt/certs, /opt/tls\n/\n  \nnot-absolute"); err != nil {
		t.Fatal(err)
	}
	roots = s.certificateReadRoots()
	for _, want := range []string{"/opt/tls", "/mnt/certs"} {
		if !has(want) {
			t.Errorf("configured root %q missing from %v", want, roots)
		}
	}
	seen := map[string]int{}
	for _, r := range roots {
		seen[r]++
		if r == "/" || !filepath.IsAbs(r) {
			t.Errorf("unusable root %q kept in %v", r, roots)
		}
	}
	if seen["/opt/tls"] != 1 {
		t.Errorf("duplicate root not collapsed: %v", roots)
	}
	if _, err := confinedReadPath("/opt/tls/site.pem", roots); err != nil {
		t.Errorf("configured root should allow its files: %v", err)
	}
	if _, err := confinedReadPath("/etc/shadow", roots); err == nil {
		t.Error("/etc/shadow must stay unreadable with a realistic root set")
	}
}

func mustRejectPath(t *testing.T, p string, roots []string) error {
	t.Helper()
	got, err := confinedReadPath(p, roots)
	if err == nil {
		t.Errorf("%q should be refused, got %q", p, got)
	}
	return err
}
