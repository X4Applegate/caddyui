package server

import (
	"fmt"
	"path/filepath"
	"strings"
)

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
