package server

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/X4Applegate/caddyui/internal/models"
)

func referencedCertificateIDs(proxyHosts []models.ProxyHost, redirectionHosts []models.RedirectionHost, rawRoutes []models.RawRoute) map[int64]bool {
	referenced := make(map[int64]bool)
	for _, host := range proxyHosts {
		if host.CertificateID != 0 {
			referenced[host.CertificateID] = true
		}
	}
	for _, host := range redirectionHosts {
		if host.CertificateID != 0 {
			referenced[host.CertificateID] = true
		}
	}
	for _, route := range rawRoutes {
		if route.CertificateID != 0 {
			referenced[route.CertificateID] = true
		}
	}
	return referenced
}

func isUnusedCustomCertificate(cert models.Certificate, referenced map[int64]bool) bool {
	if cert.ID == 0 || referenced[cert.ID] {
		return false
	}
	return cert.Source == models.CertSourcePEM || cert.Source == models.CertSourcePath
}

func summarizeCertificateNames(certs []models.Certificate, limit int) string {
	if limit < 1 {
		limit = 1
	}
	names := make([]string, 0, min(len(certs), limit))
	for _, cert := range certs {
		if len(names) == limit {
			break
		}
		name := strings.TrimSpace(cert.Name)
		if name == "" {
			name = fmt.Sprintf("Certificate #%d", cert.ID)
		}
		names = append(names, name)
	}
	summary := strings.Join(names, ", ")
	if remaining := len(certs) - len(names); remaining > 0 {
		summary += fmt.Sprintf(" and %d more", remaining)
	}
	return summary
}

func unusedCertificateFingerprint(certs []models.Certificate, referenced map[int64]bool) string {
	ids := make([]int64, 0, len(certs))
	for _, cert := range certs {
		if isUnusedCustomCertificate(cert, referenced) {
			ids = append(ids, cert.ID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(id, 10)
	}
	return strings.Join(parts, ",")
}

func unusedCertificateDismissalKey(serverID int64) string {
	return fmt.Sprintf("dashboard_unused_certificates_dismissed_%d", serverID)
}
