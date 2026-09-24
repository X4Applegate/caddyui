// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/X4Applegate/caddyui/internal/models"
)

// settingCertificateReadRoots (v2.53.0) holds extra absolute directories
// CaddyUI is allowed to read certificate and key files from, one per line
// (commas accepted). It extends defaultCertificateReadRoots for operators
// who mount their certificate volume somewhere unconventional.
const settingCertificateReadRoots = "certificate_read_roots"

// defaultCertificateReadRoots are the conventional places a certificate
// volume is mounted. They are only *candidate* roots: a root that does not
// exist in this container simply never matches anything.
var defaultCertificateReadRoots = []string{
	"/etc/caddy",
	"/etc/ssl",
	"/etc/letsencrypt",
	"/certs",
	"/data",
}

// safeAbsolutePath accepts an operator-supplied file system path only when
// it is absolute, contains no ".." segment and is already in clean form, and
// returns it cleaned. Certificate file paths and export directories are
// typed into forms by an admin, so they are trusted in the sense that the
// admin chooses them — but they are still request input, and every read or
// write that uses one goes through this guard so a stray "../" can never
// walk out of the directory the admin meant. v2.41.0.
func safeAbsolutePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", fmt.Errorf("no path given")
	}
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("path %q must not contain \"..\"", p)
	}
	clean := filepath.Clean(p)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("path %q must be absolute", p)
	}
	if strings.Contains(clean, "..") {
		return "", fmt.Errorf("path %q must not contain \"..\"", p)
	}
	return clean, nil
}

// confinedReadPath vets an operator-supplied path with safeAbsolutePath and
// then requires it to sit inside one of roots, returning the path to actually
// open. Review finding #8 (2026-09-21): safeAbsolutePath blocks "../" but by
// itself confines nothing, so an admin-configured certificate path could name
// any absolute file the process can read (/etc/shadow, another tenant's key).
// Admins are already write-trusted, so this is defence in depth rather than a
// privilege boundary — but "admin typed it into a form" is a weaker claim than
// "the file is in a directory this deployment is meant to read from", and the
// containment costs nothing.
//
// Symlinks are resolved on both sides before comparing, so a symlink planted
// inside an allowed root cannot be used to step outside it, and the resolved
// path is what the caller opens (no re-resolution between check and read).
// A path that does not exist yet keeps its cleaned form and is matched
// lexically; the subsequent read fails on its own.
//
// Fails closed: with no usable roots, nothing is readable. v2.53.0.
func confinedReadPath(p string, roots []string) (string, error) {
	clean, err := safeAbsolutePath(p)
	if err != nil {
		return "", err
	}
	usable := normalizeReadRoots(roots)
	if len(usable) == 0 {
		return "", fmt.Errorf("path %q is not inside a directory CaddyUI may read certificates from, and no such directory is configured (Settings → Security → Extra certificate directories)", clean)
	}
	target := resolveSymlinks(clean)
	for _, root := range usable {
		if pathWithinRoot(target, resolveSymlinks(root)) {
			return target, nil
		}
	}
	return "", fmt.Errorf("path %q is outside the directories CaddyUI may read certificates from (%s) — mount the directory and add it under Settings → Security → Extra certificate directories, or paste the PEM instead", clean, strings.Join(usable, ", "))
}

// normalizeReadRoots cleans, validates and de-duplicates candidate roots,
// dropping anything empty, relative, traversing, or equal to "/" — a root of
// "/" would allow every path and quietly defeat the whole check.
func normalizeReadRoots(roots []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		clean, err := safeAbsolutePath(r)
		if err != nil || clean == "/" || seen[clean] {
			continue
		}
		seen[clean] = true
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

// pathWithinRoot reports whether path is root itself or sits beneath it.
// Compares path segments, so /data-other is not treated as inside /data.
func pathWithinRoot(path, root string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, strings.TrimSuffix(root, string(filepath.Separator))+string(filepath.Separator))
}

// resolveSymlinks returns the fully resolved form of p, or p unchanged when
// it cannot be resolved (most often because it does not exist).
func resolveSymlinks(p string) string {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p
	}
	return resolved
}

// certificateReadRoots is the allowlist confinedReadPath enforces: the
// directory holding CaddyUI's own database, every configured node's mounted
// Caddy data volume (that is where findStorageCertificate looks), the
// conventional certificate locations, and whatever the operator added under
// settingCertificateReadRoots. Computed per call so adding a node or editing
// the setting takes effect without a restart. v2.53.0.
func (s *Server) certificateReadRoots() []string {
	roots := make([]string, 0, len(defaultCertificateReadRoots)+8)
	if s.DBPath != "" {
		roots = append(roots, filepath.Dir(s.DBPath))
	}
	if servers, err := models.ListCaddyServers(s.DB); err == nil {
		for _, srv := range servers {
			if dir := strings.TrimSpace(srv.DataDir); dir != "" {
				roots = append(roots, dir)
			}
		}
	}
	roots = append(roots, defaultCertificateReadRoots...)
	raw := mustGetSetting(s.DB, settingCertificateReadRoots)
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' }) {
		if dir := strings.TrimSpace(field); dir != "" {
			roots = append(roots, dir)
		}
	}
	return normalizeReadRoots(roots)
}
