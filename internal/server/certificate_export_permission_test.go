// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io/fs"
	"os"
	"strings"
	"testing"
)

// v2.61.2 (discussion #127): Caddy's data directory is root-only (0700) and the
// CaddyUI container runs as uid 10001. Listing it failed with "permission
// denied", which was swallowed and reported as "Caddy has not stored a
// certificate for … yet (looked in /caddy-data)" — sending people looking for a
// certificate that was sitting right there.

func denyStorage(t *testing.T, dirDenied, fileDenied bool) {
	t.Helper()
	origDir, origFile := storageReadDir, storageReadFile
	t.Cleanup(func() { storageReadDir, storageReadFile = origDir, origFile })
	perm := &fs.PathError{Op: "open", Path: "x", Err: fs.ErrPermission}
	if dirDenied {
		storageReadDir = func(name string) ([]os.DirEntry, error) {
			if strings.HasSuffix(name, "/caddy/certificates") || strings.HasSuffix(name, "/certificates") {
				return nil, perm
			}
			return origDir(name)
		}
	}
	if fileDenied {
		storageReadFile = func(path string, roots []string) ([]byte, error) { return nil, perm }
	}
}

func TestUnreadableCaddyStorageIsReportedAsPermissionDeniedNotAsMissing(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/caddy/certificates/acme-v02.api.letsencrypt.org-directory", 0o755); err != nil {
		t.Fatal(err)
	}
	for name, deny := range map[string][2]bool{
		"the certificates directory cannot be listed": {true, false},
		"a certificate file cannot be read":           {false, true},
	} {
		t.Run(name, func(t *testing.T) {
			denyStorage(t, deny[0], deny[1])
			// Put a directory where the file would be so the file branch is reached.
			_ = os.MkdirAll(dir+"/caddy/certificates/acme-v02.api.letsencrypt.org-directory/wildcard_.domain.com", 0o755)
			_, err := findStorageCertificate(dir, []string{"*.domain.com"}, []string{dir})
			if err == nil {
				t.Fatal("expected an error")
			}
			msg := err.Error()
			if strings.Contains(msg, "has not stored a certificate") {
				t.Errorf("a permission problem was reported as a missing certificate: %s", msg)
			}
			for _, want := range []string{"not allowed to read", "permission denied", `user: "0:0"`, "read-only"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the message lacks %q: %s", want, msg)
				}
			}
		})
	}
}

// A genuinely missing certificate still says so — the message is only replaced
// when permission was actually the problem.
func TestMissingCertificateStillReportedAsMissing(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(dir+"/caddy/certificates/acme-v02.api.letsencrypt.org-directory", 0o755)
	_, err := findStorageCertificate(dir, []string{"*.domain.com"}, []string{dir})
	if err == nil || !strings.Contains(err.Error(), "has not stored a certificate for *.domain.com") {
		t.Errorf("a truly missing certificate got: %v", err)
	}
	if _, err := findStorageCertificate(t.TempDir()+"/nope", []string{"*.domain.com"}, nil); err == nil || !strings.Contains(err.Error(), "no Caddy certificate storage found") {
		t.Errorf("a missing data directory got: %v", err)
	}
}

func TestExportWriteErrorExplainsPermissionAndPassesOthersThrough(t *testing.T) {
	perm := &fs.PathError{Op: "mkdir", Path: "/exports/mail", Err: fs.ErrPermission}
	msg := exportWriteError(perm, "/exports/mail").Error()
	for _, want := range []string{"not allowed to write to /exports/mail", "uid", "run the caddyui container as root"} {
		if !strings.Contains(msg, want) {
			t.Errorf("write-permission message lacks %q: %s", want, msg)
		}
	}
	other := &fs.PathError{Op: "mkdir", Path: "/x", Err: fs.ErrNotExist}
	if got := exportWriteError(other, "/x"); got != error(other) {
		t.Errorf("an unrelated error was altered: %v", got)
	}
}
