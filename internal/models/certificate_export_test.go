package models

import (
	"strings"
	"testing"
)

func TestCertificateExportNormalizeAndValidate(t *testing.T) {
	raw, err := NormalizeCertificateExportJSON(CertificateExport{Dir: " /exports/mail "})
	if err != nil || !strings.Contains(raw, `"dir":"/exports/mail"`) || !strings.Contains(raw, `"cert_file":"fullchain.pem"`) || !strings.Contains(raw, `"key_file":"privkey.pem"`) {
		t.Fatalf("defaults: %q, %v", raw, err)
	}
	if raw, err := NormalizeCertificateExportJSON(CertificateExport{}); err != nil || raw != "" {
		t.Errorf("blank dir must encode as off: %q, %v", raw, err)
	}
	for _, bad := range []CertificateExport{
		{Dir: "exports/mail"},
		{Dir: "/exports", CertFile: "../cert.pem"},
		{Dir: "/exports", CertFile: "sub/cert.pem"},
		{Dir: "/exports", CertFile: "same.pem", KeyFile: "same.pem"},
	} {
		if _, err := NormalizeCertificateExportJSON(bad); err == nil {
			t.Errorf("%+v should be rejected", bad)
		}
	}
	c := Certificate{Export: `{"dir":"/exports/mail","cert_file":"cert.pem"}`}
	if e := c.ExportConfig(); !e.Enabled() || e.CertFile != "cert.pem" || e.KeyFile != DefaultExportKeyFile {
		t.Errorf("ExportConfig = %+v", e)
	}
	if e := (Certificate{Export: "{broken"}).ExportConfig(); e.Enabled() {
		t.Errorf("broken JSON must read as off, got %+v", e)
	}
}
