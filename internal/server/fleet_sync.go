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
}

func (s fleetSyncSummary) Changed() int {
	return s.CertificatesCreated + s.CertificatesUpdated +
		s.ProxiesCreated + s.ProxiesUpdated +
		s.RedirectsCreated + s.RedirectsUpdated +
		s.RawRoutesCreated + s.RawRoutesUpdated
}

func (s fleetSyncSummary) String() string {
	return fmt.Sprintf(
		"proxies: %d added, %d updated; redirects: %d added, %d updated; advanced routes: %d added, %d updated; managed certificates: %d added, %d updated",
		s.ProxiesCreated, s.ProxiesUpdated,
		s.RedirectsCreated, s.RedirectsUpdated,
		s.RawRoutesCreated, s.RawRoutesUpdated,
		s.CertificatesCreated, s.CertificatesUpdated,
	)
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

func (s *Server) upsertFleetManagedCertificate(sourceServerID, targetServerID int64, source models.Certificate, ownerID int64) (fleetUpsertResult, error) {
	if source.Source != models.CertSourceManaged {
		return fleetUpsertResult{}, fmt.Errorf("only Caddy-managed certificates can be copied between environments")
	}
	targetID, err := s.mappedFleetTarget(sourceServerID, models.FleetResourceCertificate, source.ID, targetServerID)
	if err != nil {
		return fleetUpsertResult{}, err
	}
	var existing *models.Certificate
	if targetID > 0 {
		existing, err = models.GetCertificate(s.DB, targetID)
		if err != nil {
			return fleetUpsertResult{}, err
		}
	} else {
		targets, err := models.ListCertificates(s.DB, targetServerID)
		if err != nil {
			return fleetUpsertResult{}, err
		}
		for i := range targets {
			if targets[i].Source == models.CertSourceManaged && sameDomainSet(targets[i].DomainList(), source.DomainList()) {
				existing = &targets[i]
				targetID = targets[i].ID
				break
			}
		}
	}
	copy := source
	copy.OwnerID = sql.NullInt64{}
	copy.OwnerEmail = ""
	copy.CreatedAt = time.Time{}
	copy.UpdatedAt = time.Time{}
	copy.CertPEM = ""
	copy.KeyPEM = ""
	copy.CertPath = ""
	copy.KeyPath = ""
	created := existing == nil
	changed := true
	if existing != nil {
		copy.ID = existing.ID
		current := *existing
		current.OwnerID = sql.NullInt64{}
		current.OwnerEmail = ""
		current.CreatedAt = time.Time{}
		current.UpdatedAt = time.Time{}
		current.CertPEM = ""
		current.KeyPEM = ""
		current.CertPath = ""
		current.KeyPath = ""
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
		return fleetUpsertResult{}, err
	}
	if err := models.SaveFleetDeployment(s.DB, sourceServerID, models.FleetResourceCertificate, source.ID, targetServerID, targetID); err != nil {
		return fleetUpsertResult{}, err
	}
	return fleetUpsertResult{ID: targetID, Created: created, Changed: changed}, nil
}

// syncFleetConfiguration performs a one-way, non-destructive merge from the
// selected managed environment into another one. Source routes are created or
// updated; target-only routes remain untouched. Per-target DNS records and
// custom certificate choices are intentionally preserved.
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
	for _, certificate := range certificates {
		if certificate.Source != models.CertSourceManaged {
			continue
		}
		result, err := s.upsertFleetManagedCertificate(sourceServerID, targetServerID, certificate, fleetOwnerID(certificate.OwnerID))
		if err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("managed certificate %q: %w", certificate.Name, err))
			continue
		}
		if result.Created {
			summary.CertificatesCreated++
		} else if result.Changed {
			summary.CertificatesUpdated++
		}
	}
	for _, proxy := range proxies {
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
