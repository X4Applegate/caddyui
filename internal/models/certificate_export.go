package models

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// v2.42.0: CertificateExport tells CaddyUI to copy a managed certificate out
// of Caddy's storage into a directory after every issuance and renewal, so
// another service (a mail server, for example) can use the certificate Caddy
// obtains. Stored as JSON in certificates.export_json; empty = off.
type CertificateExport struct {
	Dir      string `json:"dir"`
	CertFile string `json:"cert_file,omitempty"` // full chain; default fullchain.pem
	KeyFile  string `json:"key_file,omitempty"`  // private key; default privkey.pem
}

const (
	DefaultExportCertFile = "fullchain.pem"
	DefaultExportKeyFile  = "privkey.pem"
)

// Enabled reports whether an export directory is configured.
func (e CertificateExport) Enabled() bool {
	return strings.TrimSpace(e.Dir) != ""
}

// Normalized trims the fields and fills in the default file names.
func (e CertificateExport) Normalized() CertificateExport {
	out := CertificateExport{
		Dir:      strings.TrimSpace(e.Dir),
		CertFile: strings.TrimSpace(e.CertFile),
		KeyFile:  strings.TrimSpace(e.KeyFile),
	}
	if out.CertFile == "" {
		out.CertFile = DefaultExportCertFile
	}
	if out.KeyFile == "" {
		out.KeyFile = DefaultExportKeyFile
	}
	return out
}

// Validate rejects a relative directory and file names that try to leave it.
func (e CertificateExport) Validate() error {
	n := e.Normalized()
	if !n.Enabled() {
		return nil
	}
	if !strings.HasPrefix(n.Dir, "/") {
		return fmt.Errorf("export directory must be an absolute path inside the CaddyUI container, e.g. /exports/mail")
	}
	for _, f := range []string{n.CertFile, n.KeyFile} {
		if f != path.Base(f) || f == "." || f == ".." {
			return fmt.Errorf("export file names must be plain file names without directories, got %q", f)
		}
	}
	if n.CertFile == n.KeyFile {
		return fmt.Errorf("the certificate and key export files must have different names")
	}
	return nil
}

// ParseCertificateExport decodes export_json; blank means off.
func ParseCertificateExport(raw string) (CertificateExport, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return CertificateExport{}, nil
	}
	var e CertificateExport
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return CertificateExport{}, fmt.Errorf("export settings: %w", err)
	}
	return e, nil
}

// NormalizeCertificateExportJSON validates and re-encodes an export config;
// a disabled config encodes as "" so the column stays empty.
func NormalizeCertificateExportJSON(e CertificateExport) (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	n := e.Normalized()
	if !n.Enabled() {
		return "", nil
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ExportConfig is the certificate's export configuration (zero when off or
// unparsable — a broken column is treated as off rather than crashing a page).
func (c Certificate) ExportConfig() CertificateExport {
	e, err := ParseCertificateExport(c.Export)
	if err != nil {
		return CertificateExport{}
	}
	return e.Normalized()
}
