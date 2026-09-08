package server

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/X4Applegate/caddyui/internal/models"
)

type fleetUpsertResult struct {
	ID      int64
	Created bool
	Changed bool
}

type fleetSyncSummary struct {
	CertificatesCreated int
	CertificatesUpdated int
	ProxiesCreated      int
	ProxiesUpdated      int
	RedirectsCreated    int
	RedirectsUpdated    int
	RawRoutesCreated    int
	RawRoutesUpdated    int
	// v2.33.0: resources deliberately left behind because they are marked
	// node-local. Counted and reported rather than silently dropped — an
	// operator seeing "12 proxies added" needs to know three others were
	// skipped on purpose, not lost to a bug.
	ProxiesSkipped   int
	RawRoutesSkipped int
	// v2.41.0: file-path certificates whose files CaddyUI could not read were
	// copied by path reference only — the files must exist on the target.
	CertificatesByPath int
}

func (s fleetSyncSummary) Changed() int {
	return s.CertificatesCreated + s.CertificatesUpdated +
		s.ProxiesCreated + s.ProxiesUpdated +
		s.RedirectsCreated + s.RedirectsUpdated +
		s.RawRoutesCreated + s.RawRoutesUpdated
}

func (s fleetSyncSummary) String() string {
	out := fmt.Sprintf(
		"proxies: %d added, %d updated; redirects: %d added, %d updated; advanced routes: %d added, %d updated; certificates: %d added, %d updated",
		s.ProxiesCreated, s.ProxiesUpdated,
		s.RedirectsCreated, s.RedirectsUpdated,
		s.RawRoutesCreated, s.RawRoutesUpdated,
		s.CertificatesCreated, s.CertificatesUpdated,
	)
	if s.ProxiesSkipped > 0 || s.RawRoutesSkipped > 0 {
		out += fmt.Sprintf("; skipped as node-local: %d proxies, %d advanced routes",
			s.ProxiesSkipped, s.RawRoutesSkipped)
	}
	if s.CertificatesByPath > 0 {
		out += fmt.Sprintf("; %d certificate(s) copied by file path only — the files must exist on the target at the same paths", s.CertificatesByPath)
	}
	return out
}

// mappedCertificateID resolves a source certificate reference to its copy on
// the target, or 0 when the certificate has not been copied there. v2.41.0:
// a host created on the target keeps using the same custom certificate
// instead of silently falling back to Auto TLS.
func (s *Server) mappedCertificateID(sourceServerID, certificateID, targetServerID int64) int64 {
	if certificateID == 0 {
		return 0
	}
	id, err := s.mappedFleetTarget(sourceServerID, models.FleetResourceCertificate, certificateID, targetServerID)
	if err != nil {
		return 0
	}
	return id
}

func fleetOwnerID(owner sql.NullInt64) int64 {
	if owner.Valid {
		return owner.Int64
	}
	return 0
}

func (s *Server) validateFleetPair(sourceServerID, targetServerID int64) (*models.CaddyServer, *models.CaddyServer, error) {
	if sourceServerID <= 0 || targetServerID <= 0 || sourceServerID == targetServerID {
		return nil, nil, fmt.Errorf("choose two different Caddy Fleet environments")
	}
	source, err := models.GetCaddyServer(s.DB, sourceServerID)
	if err != nil {
		return nil, nil, fmt.Errorf("load source environment: %w", err)
	}
	target, err := models.GetCaddyServer(s.DB, targetServerID)
	if err != nil {
		return nil, nil, fmt.Errorf("load target environment: %w", err)
	}
	if source.Type != models.CaddyServerTypeManaged {
		return nil, nil, fmt.Errorf("source environment %q is monitoring-only", source.Name)
	}
	if target.Type != models.CaddyServerTypeManaged {
		return nil, nil, fmt.Errorf("target environment %q is monitoring-only", target.Name)
	}
	return source, target, nil
}

func (s *Server) mappedFleetTarget(sourceServerID int64, resourceKind string, sourceResourceID, targetServerID int64) (int64, error) {
	id, err := models.FleetDeploymentTarget(s.DB, sourceServerID, resourceKind, sourceResourceID, targetServerID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	exists, err := models.FleetDeploymentTargetExists(s.DB, resourceKind, id, targetServerID)
	if err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	return id, nil
}

func preserveProxyTargetPolicy(copy *models.ProxyHost, existing *models.ProxyHost, targetServerID int64) {
	copy.ServerID = targetServerID
	copy.OwnerID = sql.NullInt64{}
	copy.OwnerEmail = ""
	copy.CreatedAt = time.Time{}
	copy.UpdatedAt = time.Time{}
	if existing == nil {
		copy.ID = 0
		copy.CertificateID = 0
		copy.DNSProvider = ""
		copy.DNSProfileID = ""
		copy.DNSZoneID = ""
		copy.DNSZoneName = ""
		copy.DNSRecordID = ""
		copy.DNSSkipRecord = false
		copy.CFDNSRecordID = ""
		copy.CFZoneID = ""
		copy.PBDNSRecordID = ""
		copy.PBDomain = ""
		return
	}
	copy.ID = existing.ID
	copy.CertificateID = existing.CertificateID
	copy.DNSProvider = existing.DNSProvider
	copy.DNSProfileID = existing.DNSProfileID
	copy.DNSZoneID = existing.DNSZoneID
	copy.DNSZoneName = existing.DNSZoneName
	copy.DNSRecordID = existing.DNSRecordID
	copy.DNSSkipRecord = existing.DNSSkipRecord
	copy.CFDNSRecordID = existing.CFDNSRecordID
	copy.CFZoneID = existing.CFZoneID
	copy.PBDNSRecordID = existing.PBDNSRecordID
	copy.PBDomain = existing.PBDomain
}

func (s *Server) upsertFleetProxyHost(sourceServerID, targetServerID int64, source models.ProxyHost, ownerID int64) (fleetUpsertResult, error) {
	targetID, err := s.mappedFleetTarget(sourceServerID, models.FleetResourceProxy, source.ID, targetServerID)
	if err != nil {
		return fleetUpsertResult{}, err
	}
	var existing *models.ProxyHost
	if targetID > 0 {
		existing, err = models.GetProxyHost(s.DB, targetID)
		if err != nil {
			return fleetUpsertResult{}, err
		}
	} else {
		targets, err := models.ListProxyHosts(s.DB, targetServerID, 0, true, nil)
		if err != nil {
			return fleetUpsertResult{}, err
		}
		for i := range targets {
			if sameDomainSet(targets[i].DomainList(), source.DomainList()) {
				existing = &targets[i]
				targetID = targets[i].ID
				break
			}
		}
	}
	if existing == nil || !sameDomainSet(existing.DomainList(), source.DomainList()) {
		if conflict, err := models.DomainsConflict(s.DB, targetServerID, source.DomainList(), targetID, 0); err != nil {
			return fleetUpsertResult{}, err
		} else if conflict != "" {
			return fleetUpsertResult{}, fmt.Errorf("domain %q is already claimed on the target environment", conflict)
		}
	}

	copy := source
	preserveProxyTargetPolicy(&copy, existing, targetServerID)
	if existing == nil {
		copy.CertificateID = s.mappedCertificateID(sourceServerID, source.CertificateID, targetServerID)
	}
	created := existing == nil
	changed := true
	if existing != nil {
		current := *existing
		preserveProxyTargetPolicy(&current, existing, targetServerID)
		changed = !reflect.DeepEqual(current, copy) || fleetOwnerID(existing.OwnerID) != ownerID
	}
	if created {
		targetID, err = models.CreateProxyHost(s.DB, targetServerID, ownerID, &copy)
	} else if changed {
		err = models.UpdateProxyHost(s.DB, &copy)
		if err == nil {
			err = models.SetProxyHostOwner(s.DB, copy.ID, ownerID)
		}
	}
	if err != nil {
		return fleetUpsertResult{}, err
	}
	if err := models.SaveFleetDeployment(s.DB, sourceServerID, models.FleetResourceProxy, source.ID, targetServerID, targetID); err != nil {
		return fleetUpsertResult{}, err
	}
	return fleetUpsertResult{ID: targetID, Created: created, Changed: changed}, nil
}

func preserveRedirectTargetPolicy(copy *models.RedirectionHost, existing *models.RedirectionHost) {
	copy.OwnerID = sql.NullInt64{}
	copy.OwnerEmail = ""
	copy.CreatedAt = time.Time{}
	copy.UpdatedAt = time.Time{}
	if existing == nil {
		copy.ID = 0
		copy.CertificateID = 0
		copy.DNSProvider = ""
		copy.DNSProfileID = ""
		copy.DNSZoneID = ""
		copy.DNSZoneName = ""
		copy.DNSRecordID = ""
		copy.DNSSkipRecord = false
		return
	}
	copy.ID = existing.ID
	copy.CertificateID = existing.CertificateID
	copy.DNSProvider = existing.DNSProvider
	copy.DNSProfileID = existing.DNSProfileID
	copy.DNSZoneID = existing.DNSZoneID
	copy.DNSZoneName = existing.DNSZoneName
	copy.DNSRecordID = existing.DNSRecordID
	copy.DNSSkipRecord = existing.DNSSkipRecord
}

func (s *Server) upsertFleetRedirectionHost(sourceServerID, targetServerID int64, source models.RedirectionHost, ownerID int64) (fleetUpsertResult, error) {
	targetID, err := s.mappedFleetTarget(sourceServerID, models.FleetResourceRedirect, source.ID, targetServerID)
	if err != nil {
		return fleetUpsertResult{}, err
	}
	var existing *models.RedirectionHost
	if targetID > 0 {
		existing, err = models.GetRedirectionHost(s.DB, targetID)
		if err != nil {
			return fleetUpsertResult{}, err
		}
	} else {
		targets, err := models.ListRedirectionHosts(s.DB, targetServerID, 0, true, nil)
		if err != nil {
			return fleetUpsertResult{}, err
		}
		for i := range targets {
			if sameDomainSet(targets[i].DomainList(), source.DomainList()) {
				existing = &targets[i]
				targetID = targets[i].ID
				break
			}
		}
	}
	if existing == nil || !sameDomainSet(existing.DomainList(), source.DomainList()) {
		if conflict, err := models.DomainsConflict(s.DB, targetServerID, source.DomainList(), 0, targetID); err != nil {
			return fleetUpsertResult{}, err
		} else if conflict != "" {
			return fleetUpsertResult{}, fmt.Errorf("domain %q is already claimed on the target environment", conflict)
		}
	}

	copy := source
	preserveRedirectTargetPolicy(&copy, existing)
	if existing == nil {
		copy.CertificateID = s.mappedCertificateID(sourceServerID, source.CertificateID, targetServerID)
	}
	created := existing == nil
	changed := true
	if existing != nil {
		current := *existing
		preserveRedirectTargetPolicy(&current, existing)
		changed = !reflect.DeepEqual(current, copy) || fleetOwnerID(existing.OwnerID) != ownerID
	}
	if created {
		targetID, err = models.CreateRedirectionHost(s.DB, targetServerID, ownerID, &copy)
	} else if changed {
		err = models.UpdateRedirectionHost(s.DB, &copy)
		if err == nil {
			err = models.SetRedirectionHostOwner(s.DB, copy.ID, ownerID)
		}
	}
	if err != nil {
		return fleetUpsertResult{}, err
	}
	if err := models.SaveFleetDeployment(s.DB, sourceServerID, models.FleetResourceRedirect, source.ID, targetServerID, targetID); err != nil {
		return fleetUpsertResult{}, err
	}
	return fleetUpsertResult{ID: targetID, Created: created, Changed: changed}, nil
}

func rawRouteIdentityMatches(a, b models.RawRoute) bool {
	aHosts, bHosts := rawRouteHosts(a), rawRouteHosts(b)
	if len(aHosts) > 0 || len(bHosts) > 0 {
		return len(aHosts) > 0 && len(bHosts) > 0 && sameDomainSet(aHosts, bHosts)
	}
	return strings.EqualFold(strings.TrimSpace(a.Label), strings.TrimSpace(b.Label))
}

func preserveRawRouteTargetPolicy(copy *models.RawRoute, existing *models.RawRoute) {
	copy.OwnerID = sql.NullInt64{}
	copy.OwnerEmail = ""
	copy.CreatedAt = time.Time{}
	copy.UpdatedAt = time.Time{}
	if existing == nil {
		copy.ID = 0
		copy.CertificateID = 0
		copy.DNSProvider = ""
		copy.DNSProfileID = ""
		copy.DNSZoneID = ""
		copy.DNSZoneName = ""
		copy.DNSRecordID = ""
		copy.DNSSkipRecord = false
		return
	}
	copy.ID = existing.ID
	copy.CertificateID = existing.CertificateID
	copy.DNSProvider = existing.DNSProvider
	copy.DNSProfileID = existing.DNSProfileID
	copy.DNSZoneID = existing.DNSZoneID
	copy.DNSZoneName = existing.DNSZoneName
	copy.DNSRecordID = existing.DNSRecordID
	copy.DNSSkipRecord = existing.DNSSkipRecord
}

func (s *Server) upsertFleetRawRoute(sourceServerID, targetServerID int64, source models.RawRoute, ownerID int64) (fleetUpsertResult, error) {
	targetID, err := s.mappedFleetTarget(sourceServerID, models.FleetResourceRawRoute, source.ID, targetServerID)
	if err != nil {
		return fleetUpsertResult{}, err
	}
	var existing *models.RawRoute
	if targetID > 0 {
		existing, err = models.GetRawRoute(s.DB, targetID)
		if err != nil {
			return fleetUpsertResult{}, err
		}
	} else {
		targets, err := models.ListRawRoutes(s.DB, targetServerID, 0, true, nil)
		if err != nil {
			return fleetUpsertResult{}, err
		}
		for i := range targets {
			if rawRouteIdentityMatches(targets[i], source) {
				existing = &targets[i]
				targetID = targets[i].ID
				break
			}
		}
	}
	if existing == nil || !rawRouteIdentityMatches(*existing, source) {
		if conflict, err := models.DomainsConflict(s.DB, targetServerID, rawRouteHosts(source), 0, 0); err != nil {
			return fleetUpsertResult{}, err
		} else if conflict != "" {
			return fleetUpsertResult{}, fmt.Errorf("domain %q is already claimed on the target environment", conflict)
		}
	}

	copy := source
	preserveRawRouteTargetPolicy(&copy, existing)
	if existing == nil {
		copy.CertificateID = s.mappedCertificateID(sourceServerID, source.CertificateID, targetServerID)
	}
	created := existing == nil
	changed := true
	if existing != nil {
		current := *existing
		preserveRawRouteTargetPolicy(&current, existing)
		changed = !reflect.DeepEqual(current, copy) || fleetOwnerID(existing.OwnerID) != ownerID
	}
	if created {
		targetID, err = models.CreateRawRoute(s.DB, targetServerID, ownerID, &copy)
	} else if changed {
		err = models.UpdateRawRoute(s.DB, &copy)
		if err == nil {
			err = models.SetRawRouteOwner(s.DB, copy.ID, ownerID)
		}
	}
	if err != nil {
		return fleetUpsertResult{}, err
	}
	if err := models.SaveFleetDeployment(s.DB, sourceServerID, models.FleetResourceRawRoute, source.ID, targetServerID, targetID); err != nil {
		return fleetUpsertResult{}, err
	}
	return fleetUpsertResult{ID: targetID, Created: created, Changed: changed}, nil
}

// fleetCertificateCopy is how a source certificate is represented on a target
// node. Managed definitions copy their DNS-01 settings only — each node
// orders its own certificate. Stored PEMs copy their content. v2.41.0: a
// file-path certificate is copied as stored PEM when CaddyUI can read both
// files (the target host cannot see the source's disk, so a path would point
// at nothing there), and by path reference otherwise, in which case the
// files must exist on the target at the same paths; byPath reports that.
func fleetCertificateCopy(source models.Certificate) (copy models.Certificate, byPath bool) {
	copy = source
	copy.OwnerID = sql.NullInt64{}
	copy.OwnerEmail = ""
	copy.CreatedAt = time.Time{}
	copy.UpdatedAt = time.Time{}
	switch source.Source {
	case models.CertSourceManaged:
		copy.CertPEM, copy.KeyPEM, copy.CertPath, copy.KeyPath = "", "", "", ""
	case models.CertSourcePEM:
		copy.CertPath, copy.KeyPath = "", ""
		copy.DNSProvider, copy.DNSProfileID = "", ""
	case models.CertSourcePath:
		copy.DNSProvider, copy.DNSProfileID = "", ""
		certPEM, certErr := readCertificateFile(source.CertPath)
		keyPEM, keyErr := readCertificateFile(source.KeyPath)
		if certErr == nil && keyErr == nil && parsePEMLeaf(string(certPEM)) != nil && strings.Contains(string(keyPEM), "PRIVATE KEY") {
			copy.Source = models.CertSourcePEM
			copy.CertPEM, copy.KeyPEM = strings.TrimSpace(string(certPEM)), strings.TrimSpace(string(keyPEM))
			copy.CertPath, copy.KeyPath = "", ""
		} else {
			copy.CertPEM, copy.KeyPEM = "", ""
			byPath = true
		}
	}
	return copy, byPath
}

// fleetCertificateMatches pairs a source certificate with a target row that
// has no deployment mapping yet: same domain set and the same kind (managed
// with managed, custom with custom — a PEM copy of a file-path source is
// still custom). Name breaks ties.
func fleetCertificateMatches(target, source models.Certificate) bool {
	if !sameDomainSet(target.DomainList(), source.DomainList()) {
		return false
	}
	return (target.Source == models.CertSourceManaged) == (source.Source == models.CertSourceManaged)
}

// upsertFleetCertificate creates or updates the target's copy of source
// (see fleetCertificateCopy) and records the deployment mapping. byPath is
// true when a file-path certificate could only be copied by reference.
func (s *Server) upsertFleetCertificate(sourceServerID, targetServerID int64, source models.Certificate, ownerID int64) (result fleetUpsertResult, byPath bool, err error) {
	targetID, err := s.mappedFleetTarget(sourceServerID, models.FleetResourceCertificate, source.ID, targetServerID)
	if err != nil {
		return fleetUpsertResult{}, false, err
	}
	var existing *models.Certificate
	if targetID > 0 {
		existing, err = models.GetCertificate(s.DB, targetID)
		if err != nil {
			return fleetUpsertResult{}, false, err
		}
	} else {
		targets, err := models.ListCertificates(s.DB, targetServerID)
		if err != nil {
			return fleetUpsertResult{}, false, err
		}
		for i := range targets {
			if fleetCertificateMatches(targets[i], source) && (existing == nil || targets[i].Name == source.Name) {
				existing = &targets[i]
				targetID = targets[i].ID
			}
		}
	}
	copy, byPath := fleetCertificateCopy(source)
	created := existing == nil
	changed := true
	if existing != nil {
		copy.ID = existing.ID
		current := *existing
		current.OwnerID = sql.NullInt64{}
		current.OwnerEmail = ""
		current.CreatedAt = time.Time{}
		current.UpdatedAt = time.Time{}
		if sameDomainSet(current.DomainList(), copy.DomainList()) {
			current.Domains = copy.Domains
		}
		changed = !reflect.DeepEqual(current, copy) || fleetOwnerID(existing.OwnerID) != ownerID
	}
	if created {
		copy.ID = 0
		targetID, err = models.CreateCertificate(s.DB, targetServerID, ownerID, &copy)
	} else if changed {
		copy.ID = existing.ID
		err = models.UpdateCertificate(s.DB, &copy)
		if err == nil {
			err = models.SetCertificateOwner(s.DB, copy.ID, ownerID)
		}
	}
	if err != nil {
		return fleetUpsertResult{}, byPath, err
	}
	if err := models.SaveFleetDeployment(s.DB, sourceServerID, models.FleetResourceCertificate, source.ID, targetServerID, targetID); err != nil {
		return fleetUpsertResult{}, byPath, err
	}
	return fleetUpsertResult{ID: targetID, Created: created, Changed: changed}, byPath, nil
}

// syncFleetConfiguration performs a one-way, non-destructive merge from the
// selected managed environment into another one. Source routes are created or
// updated; target-only routes remain untouched. Per-target DNS records and an
// existing target host's certificate choice are intentionally preserved; a
// host created by the sync references the copy of its source certificate.
func (s *Server) syncFleetConfiguration(actor string, sourceServerID, targetServerID int64) (fleetSyncSummary, error) {
	if _, _, err := s.validateFleetPair(sourceServerID, targetServerID); err != nil {
		return fleetSyncSummary{}, err
	}
	s.fleetDeployMu.Lock()
	defer s.fleetDeployMu.Unlock()

	certificates, err := models.ListCertificates(s.DB, sourceServerID)
	if err != nil {
		return fleetSyncSummary{}, fmt.Errorf("list source certificates: %w", err)
	}
	proxies, err := models.ListProxyHosts(s.DB, sourceServerID, 0, true, nil)
	if err != nil {
		return fleetSyncSummary{}, fmt.Errorf("list source proxy hosts: %w", err)
	}
	redirects, err := models.ListRedirectionHosts(s.DB, sourceServerID, 0, true, nil)
	if err != nil {
		return fleetSyncSummary{}, fmt.Errorf("list source redirects: %w", err)
	}
	rawRoutes, err := models.ListRawRoutes(s.DB, sourceServerID, 0, true, nil)
	if err != nil {
		return fleetSyncSummary{}, fmt.Errorf("list source advanced routes: %w", err)
	}

	var summary fleetSyncSummary
	var syncErrors []error
	// v2.41.0: every certificate travels, not only managed definitions —
	// see fleetCertificateCopy. Certificates go first so the hosts copied
	// below can resolve their certificate references (mappedCertificateID).
	for _, certificate := range certificates {
		result, byPath, err := s.upsertFleetCertificate(sourceServerID, targetServerID, certificate, fleetOwnerID(certificate.OwnerID))
		if err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("certificate %q: %w", certificate.Name, err))
			continue
		}
		if byPath {
			summary.CertificatesByPath++
		}
		if result.Created {
			summary.CertificatesCreated++
		} else if result.Changed {
			summary.CertificatesUpdated++
		}
	}
	for _, proxy := range proxies {
		// v2.33.0: node-local hosts never leave their node. Their upstream
		// (a Docker service name, a VPN address) means nothing on the target,
		// so copying them would create a route pointing at nothing.
		if proxy.NodeLocal {
			summary.ProxiesSkipped++
			continue
		}
		result, err := s.upsertFleetProxyHost(sourceServerID, targetServerID, proxy, fleetOwnerID(proxy.OwnerID))
		if err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("proxy %q: %w", proxy.Domains, err))
			continue
		}
		if result.Created {
			summary.ProxiesCreated++
		} else if result.Changed {
			summary.ProxiesUpdated++
		}
	}
	for _, redirect := range redirects {
		result, err := s.upsertFleetRedirectionHost(sourceServerID, targetServerID, redirect, fleetOwnerID(redirect.OwnerID))
		if err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("redirect %q: %w", redirect.Domains, err))
			continue
		}
		if result.Created {
			summary.RedirectsCreated++
		} else if result.Changed {
			summary.RedirectsUpdated++
		}
	}
	for _, rawRoute := range rawRoutes {
		if rawRoute.NodeLocal { // v2.33.0 — see the proxy loop above
			summary.RawRoutesSkipped++
			continue
		}
		result, err := s.upsertFleetRawRoute(sourceServerID, targetServerID, rawRoute, fleetOwnerID(rawRoute.OwnerID))
		if err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("advanced route %q: %w", rawRoute.Label, err))
			continue
		}
		if result.Created {
			summary.RawRoutesCreated++
		} else if result.Changed {
			summary.RawRoutesUpdated++
		}
	}

	detail := fmt.Sprintf("source_server=%d target_server=%d %s", sourceServerID, targetServerID, summary.String())
	_ = models.LogActivity(s.DB, targetServerID, actor, "fleet_config_sync", fmt.Sprintf("server:%d", targetServerID), detail, len(syncErrors) == 0)
	return summary, errors.Join(syncErrors...)
}
