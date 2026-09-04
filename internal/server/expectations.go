package server

// v2.38.0: post-apply expectations with automatic rollback.
//
// Every config sync ends by running the enabled expectations of every proxy
// host on that server against the live Caddy (see verifyAppliedConfig). If
// any fail and auto-rollback is on, the previous live config — which
// syncCaddy still holds in memory — is loaded back into Caddy, a "hold" is
// recorded for the server so later automatic syncs don't push the same
// broken state again, and every page shows a banner until the operator
// re-applies or accepts the rolled-back state. Results are kept in memory
// per process, like the App health dots; the Activity log keeps the history.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
	"github.com/go-chi/chi/v5"
)

const (
	// settingExpectationsAutoRollback: "" or "1" = roll back on failure
	// (default); "0" = report only.
	settingExpectationsAutoRollback = "expectations_auto_rollback"
	expectationProbeTimeout         = 10 * time.Second
	expectationParallelism          = 4
	syncHoldKeyPrefix               = "sync_hold_server_"
)

func expectationsAutoRollbackEnabled(s *Server) bool {
	return mustGetSetting(s.DB, settingExpectationsAutoRollback) != "0"
}

// expectationResult is the outcome of one expectation against one host.
type expectationResult struct {
	HostID      int64
	Domain      string
	Expectation models.HostExpectation
	URL         string
	OK          bool
	Status      int
	LatencyMS   int64
	Location    string
	Error       string
	CheckedAt   time.Time
}

// Summary is one line for banners, activity entries and the health page.
func (r expectationResult) Summary() string {
	s := r.Expectation.Describe()
	if r.OK {
		return fmt.Sprintf("%s — ok (%d in %d ms)", s, r.Status, r.LatencyMS)
	}
	if r.Error != "" {
		return fmt.Sprintf("%s — FAILED: %s", s, r.Error)
	}
	return fmt.Sprintf("%s — FAILED (%d in %d ms)", s, r.Status, r.LatencyMS)
}

// expectationRun summarises one pass over a server.
type expectationRun struct {
	ServerID   int64
	At         time.Time
	Total      int
	Failed     int
	RolledBack bool
}

func (s *Server) storeExpectationResults(serverID int64, results []expectationResult, rolledBack bool) {
	s.expectationMu.Lock()
	defer s.expectationMu.Unlock()
	if s.expectationResults == nil {
		s.expectationResults = map[int64][]expectationResult{}
	}
	if s.expectationRuns == nil {
		s.expectationRuns = map[int64]expectationRun{}
	}
	byHost := map[int64][]expectationResult{}
	failed := 0
	for _, r := range results {
		byHost[r.HostID] = append(byHost[r.HostID], r)
		if !r.OK {
			failed++
		}
	}
	for id, rs := range byHost {
		s.expectationResults[id] = rs
	}
	if len(results) > 0 {
		s.expectationRuns[serverID] = expectationRun{ServerID: serverID, At: time.Now(), Total: len(results), Failed: failed, RolledBack: rolledBack}
	}
}

// expectationResultsFor returns the latest results recorded for a host.
func (s *Server) expectationResultsFor(hostID int64) []expectationResult {
	s.expectationMu.RLock()
	defer s.expectationMu.RUnlock()
	return append([]expectationResult(nil), s.expectationResults[hostID]...)
}

// evaluateExpectation performs one request and judges it.
func evaluateExpectation(ctx context.Context, domain string, e models.HostExpectation) expectationResult {
	e = e.Normalized()
	res := expectationResult{Domain: domain, Expectation: e, CheckedAt: time.Now()}
	target := (&url.URL{Scheme: e.Scheme, Host: domain, Path: e.Path}).String()
	res.URL = target
	client := &http.Client{
		Timeout: expectationProbeTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: !e.VerifyTLS}, // nolint:gosec // opt-in per expectation
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, e.Method, target, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "caddyui-expectations/1.0")
	start := time.Now()
	resp, err := client.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	res.Location = resp.Header.Get("Location")
	var problems []string
	if e.ExpectStatus > 0 {
		if resp.StatusCode != e.ExpectStatus {
			problems = append(problems, fmt.Sprintf("HTTP %d, expected %d", resp.StatusCode, e.ExpectStatus))
		}
	} else if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		problems = append(problems, fmt.Sprintf("HTTP %d, expected 2xx/3xx", resp.StatusCode))
	}
	if e.ExpectLocation != "" && !strings.HasPrefix(res.Location, e.ExpectLocation) {
		problems = append(problems, fmt.Sprintf("Location %q does not start with %q", res.Location, e.ExpectLocation))
	}
	if e.MaxLatencyMS > 0 && res.LatencyMS > int64(e.MaxLatencyMS) {
		problems = append(problems, fmt.Sprintf("%d ms, limit %d ms", res.LatencyMS, e.MaxLatencyMS))
	}
	if len(problems) > 0 {
		res.Error = strings.Join(problems, "; ")
		return res
	}
	res.OK = true
	return res
}

// runHostExpectations evaluates every active expectation of one host, in
// parallel, and records the results. A host with no domain or no
// expectations yields nothing.
func (s *Server) runHostExpectations(ctx context.Context, host models.ProxyHost) []expectationResult {
	domains := host.DomainList()
	exps := host.ActiveExpectations()
	if len(domains) == 0 || len(exps) == 0 {
		return nil
	}
	domain := domains[0]
	results := make([]expectationResult, len(exps))
	sem := make(chan struct{}, expectationParallelism)
	var wg sync.WaitGroup
	for i, e := range exps {
		wg.Add(1)
		go func(i int, e models.HostExpectation) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := evaluateExpectation(ctx, domain, e)
			r.HostID = host.ID
			results[i] = r
		}(i, e)
	}
	wg.Wait()
	return results
}

// runServerExpectations evaluates every enabled host's expectations on a
// server and stores the results. Hosts are run in list order.
func (s *Server) runServerExpectations(ctx context.Context, serverID int64) ([]expectationResult, int) {
	hosts, err := models.ListProxyHosts(s.DB, serverID, 0, true, nil)
	if err != nil {
		log.Printf("expectations: list proxy hosts for server %d: %v", serverID, err)
		return nil, 0
	}
	var all []expectationResult
	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		all = append(all, s.runHostExpectations(ctx, h)...)
	}
	failed := 0
	for _, r := range all {
		if !r.OK {
			failed++
		}
	}
	return all, failed
}

// syncHold records that a server's live config was rolled back (or that a
// rollback was attempted) after a failed post-apply check. While a hold is
// set, automatic syncs for that server are skipped so the broken state is
// not pushed again; the operator re-applies or accepts the rolled-back
// config from the banner. Persisted as a setting so it survives restarts.
type syncHold struct {
	ServerID   int64     `json:"server_id"`
	ServerName string    `json:"server_name"`
	At         time.Time `json:"at"`
	RolledBack bool      `json:"rolled_back"`
	Failed     []string  `json:"failed"`
	Detail     string    `json:"detail"`
}

func syncHoldKey(serverID int64) string { return fmt.Sprintf("%s%d", syncHoldKeyPrefix, serverID) }

func (s *Server) syncHoldFor(serverID int64) *syncHold {
	raw := mustGetSetting(s.DB, syncHoldKey(serverID))
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var h syncHold
	if err := json.Unmarshal([]byte(raw), &h); err != nil {
		return nil
	}
	return &h
}

func (s *Server) setSyncHold(h syncHold) {
	b, err := json.Marshal(h)
	if err != nil {
		return
	}
	if err := models.SetSetting(s.DB, syncHoldKey(h.ServerID), string(b)); err != nil {
		log.Printf("expectations: save hold for server %d: %v", h.ServerID, err)
	}
}

func (s *Server) clearSyncHold(serverID int64) {
	if err := models.SetSetting(s.DB, syncHoldKey(serverID), ""); err != nil {
		log.Printf("expectations: clear hold for server %d: %v", serverID, err)
	}
}

// activeSyncHolds lists every server currently held, for the site-wide banner.
func (s *Server) activeSyncHolds(servers []models.CaddyServer) []syncHold {
	var out []syncHold
	for _, sr := range servers {
		if h := s.syncHoldFor(sr.ID); h != nil {
			if h.ServerName == "" {
				h.ServerName = sr.Name
			}
			out = append(out, *h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerID < out[j].ServerID })
	return out
}

// verifyAppliedConfig runs the server's expectations right after a sync
// has been applied. previous is the live config as fetched before the
// apply; on failure with auto-rollback on it is loaded back into Caddy
// through client. Returns an error when the applied config was rolled back
// (or a rollback was needed but failed) so callers can surface it.
func (s *Server) verifyAppliedConfig(serverID int64, serverName string, client *caddy.Client, previous map[string]any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*expectationProbeTimeout)
	defer cancel()
	results, failed := s.runServerExpectations(ctx, serverID)
	if len(results) == 0 {
		return nil
	}
	autoRollback := expectationsAutoRollbackEnabled(s)
	rolledBack := false
	var failures []string
	for _, r := range results {
		if !r.OK {
			failures = append(failures, r.Summary())
		}
	}
	if failed == 0 {
		s.storeExpectationResults(serverID, results, false)
		_ = models.LogActivity(s.DB, serverID, "system", "expectations_passed", "", fmt.Sprintf("%d check(s) passed after sync", len(results)), true)
		return nil
	}
	detail := fmt.Sprintf("%d of %d post-apply check(s) failed: %s", failed, len(results), strings.Join(failures, " | "))
	_ = models.LogActivity(s.DB, serverID, "system", "expectations_failed", "", detail, false)
	if !autoRollback {
		s.storeExpectationResults(serverID, results, false)
		log.Printf("expectations: server %d: %s (auto-rollback off, config left applied)", serverID, detail)
		return nil
	}
	hold := syncHold{ServerID: serverID, ServerName: serverName, At: time.Now().UTC(), Failed: failures}
	if previous == nil || len(previous) == 0 {
		hold.Detail = detail + " — no previous config was available to roll back to"
		s.setSyncHold(hold)
		s.storeExpectationResults(serverID, results, false)
		return fmt.Errorf("post-apply checks failed and no previous config was available to roll back to: %s", strings.Join(failures, "; "))
	}
	if err := client.Load(previous); err != nil {
		hold.Detail = detail + " — rollback FAILED: " + err.Error()
		s.setSyncHold(hold)
		s.storeExpectationResults(serverID, results, false)
		_ = models.LogActivity(s.DB, serverID, "system", "sync_rollback_failed", "", err.Error(), false)
		return fmt.Errorf("post-apply checks failed and rolling back also failed: %v (checks: %s)", err, strings.Join(failures, "; "))
	}
	rolledBack = true
	hold.RolledBack = true
	hold.Detail = detail
	s.setSyncHold(hold)
	s.storeExpectationResults(serverID, results, rolledBack)
	_ = models.LogActivity(s.DB, serverID, "system", "sync_rolled_back", "", detail, false)
	log.Printf("expectations: server %d: rolled back live config — %s", serverID, detail)
	return fmt.Errorf("post-apply checks failed; the live config was rolled back to its previous state: %s", strings.Join(failures, "; "))
}

// --- handlers ---------------------------------------------------------------

// runProxyHostExpectationsHandler: POST /proxy-hosts/{id}/expectations/run —
// a manual run against the live config. Never rolls anything back.
func (s *Server) runProxyHostExpectationsHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	host, err := models.GetProxyHost(s.DB, id)
	if err != nil || host == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*expectationProbeTimeout)
	defer cancel()
	results := s.runHostExpectations(ctx, *host)
	s.storeExpectationResults(s.currentServerID(r), results, false)
	failed := 0
	for _, res := range results {
		if !res.OK {
			failed++
		}
	}
	_ = models.LogActivity(s.DB, s.currentServerID(r), s.currentUserEmail(r), "expectations_run",
		fmt.Sprintf("proxy:%d", id), fmt.Sprintf("%d of %d check(s) failed", failed, len(results)), failed == 0)
	http.Redirect(w, r, fmt.Sprintf("/proxy-hosts/%d/health", id), http.StatusSeeOther)
}

func redirectBack(w http.ResponseWriter, r *http.Request) {
	back := "/"
	if u, err := url.Parse(r.Referer()); err == nil && u != nil && strings.HasPrefix(u.Path, "/") {
		back = u.Path
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// reapplySyncHandler: POST /servers/{id}/sync-reapply — clears the hold and
// pushes the saved state again (the expectations run again afterwards).
func (s *Server) reapplySyncHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	s.clearSyncHold(id)
	_ = models.LogActivity(s.DB, id, s.currentUserEmail(r), "sync_reapply", fmt.Sprintf("server:%d", id), "hold cleared by operator; re-applying saved configuration", true)
	if err := s.syncCaddy(id, true); err != nil {
		log.Printf("re-apply for server %d: %v", id, err)
	}
	redirectBack(w, r)
}

// clearSyncHoldHandler: POST /servers/{id}/sync-hold/clear — accept the
// rolled-back live config; automatic syncs resume on the next change.
func (s *Server) clearSyncHoldHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.NotFound(w, r)
		return
	}
	s.clearSyncHold(id)
	_ = models.LogActivity(s.DB, id, s.currentUserEmail(r), "sync_hold_cleared", fmt.Sprintf("server:%d", id), "operator kept the rolled-back configuration", true)
	redirectBack(w, r)
}
