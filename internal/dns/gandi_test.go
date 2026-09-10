package dns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeLiveDNS emulates the parts of Gandi's LiveDNS v5 API CaddyUI uses:
// domain listing, RRset lookup by name, create (409 on duplicate), delete.
type fakeLiveDNS struct {
	mu      sync.Mutex
	domains []string
	rrsets  map[string][]gandiRRSet // domain → sets
	auth    string
}

func (f *fakeLiveDNS) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.auth = r.Header.Get("Authorization")
		if f.auth != "Bearer pat-secret" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"code":403,"message":"Authorization failed","object":"HTTPForbidden","cause":"Forbidden"}`))
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case r.Method == "GET" && r.URL.Path == "/domains":
			var out []map[string]string
			for _, d := range f.domains {
				out = append(out, map[string]string{"fqdn": d})
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == "GET" && len(parts) == 4 && parts[2] == "records":
			domain, name := parts[1], parts[3]
			var out []gandiRRSet
			for _, rs := range f.rrsets[domain] {
				if rs.Name == name {
					out = append(out, rs)
				}
			}
			if len(out) == 0 {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"code":404,"message":"Not Found","object":"HTTPNotFound","cause":"Not Found"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == "POST" && len(parts) == 3 && parts[2] == "records":
			domain := parts[1]
			var rs gandiRRSet
			_ = json.NewDecoder(r.Body).Decode(&rs)
			for _, existing := range f.rrsets[domain] {
				if existing.Name == rs.Name && existing.Type == rs.Type {
					w.WriteHeader(409)
					_, _ = w.Write([]byte(`{"code":409,"message":"DNS Record already exists","object":"HTTPConflict","cause":"Conflict"}`))
					return
				}
			}
			if rs.TTL < 300 {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"code":400,"message":"Invalid value","object":"HTTPBadRequest","cause":"Bad Request","errors":[{"location":"body","name":"rrset_ttl","description":"must be at least 300"}]}`))
				return
			}
			f.rrsets[domain] = append(f.rrsets[domain], rs)
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"message":"DNS Record Created"}`))
		case r.Method == "DELETE" && len(parts) == 5 && parts[2] == "records":
			domain, name, rtype := parts[1], parts[3], parts[4]
			kept := f.rrsets[domain][:0]
			found := false
			for _, rs := range f.rrsets[domain] {
				if rs.Name == name && rs.Type == rtype {
					found = true
					continue
				}
				kept = append(kept, rs)
			}
			f.rrsets[domain] = kept
			if !found {
				w.WriteHeader(404)
				return
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	})
}

func newGandiTestProvider(t *testing.T, fake *fakeLiveDNS) *gandiProvider {
	t.Helper()
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	return &gandiProvider{token: "pat-secret", apiBase: srv.URL, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func TestGandiDescriptorAndFactory(t *testing.T) {
	d, ok := Lookup(Gandi)
	if !ok || d.DisplayName != "Gandi" || len(d.Credentials) != 1 || d.Credentials[0].Key != "gandi_api_token" || !d.Credentials[0].Secret {
		t.Fatalf("descriptor = %+v", d)
	}
	if Build(Gandi, map[string]string{"gandi_api_token": " "}) != nil {
		t.Error("blank token must not build a provider")
	}
	if p := Build(Gandi, map[string]string{"gandi_api_token": "pat"}); p == nil || p.ID() != Gandi {
		t.Error("token should build the Gandi provider")
	}
}

// Zones are domains, records are RRsets addressed by name/type, the apex is
// "@", TTLs are floored at 300, duplicates are refused with a clear message,
// and delete removes the set (a missing set is not an error).
func TestGandiRecordLifecycle(t *testing.T) {
	fake := &fakeLiveDNS{domains: []string{"example.com", "other.org"}, rrsets: map[string][]gandiRRSet{
		"example.com": {{Name: "www", Type: "A", TTL: 300, Values: []string{"203.0.113.9"}}, {Name: "www", Type: "TXT", TTL: 300, Values: []string{"v=spf1"}}},
	}}
	p := newGandiTestProvider(t, fake)

	if status, err := p.Ping(); err != nil || !strings.Contains(status, "2 domains") {
		t.Fatalf("ping = %q, %v", status, err)
	}
	zones, err := p.ListZones()
	if err != nil || len(zones) != 2 || zones[0].ID != "example.com" || zones[0].Name != "example.com" {
		t.Fatalf("zones = %+v, %v", zones, err)
	}
	zone := zones[0]

	// Existing sets at a name are reported, one Record per type, with values.
	found, err := p.FindRecord(zone, "www.example.com")
	if err != nil || len(found) != 2 || found[0].ID != "www/A" || found[0].Content != "203.0.113.9" || found[1].Type != "TXT" {
		t.Fatalf("find = %+v, %v", found, err)
	}
	if found, err := p.FindRecord(zone, "nothing.example.com"); err != nil || len(found) != 0 {
		t.Fatalf("missing name should be an empty result: %+v, %v", found, err)
	}

	// Create: subdomain name, TTL floored, composite ID.
	rec, err := p.CreateRecord(zone, "app.example.com", "203.0.113.5", "A", 60)
	if err != nil || rec.ID != "app/A" || rec.TTL != 300 || rec.Name != "app.example.com" {
		t.Fatalf("create = %+v, %v", rec, err)
	}
	if sets := fake.rrsets["example.com"]; len(sets) != 3 || sets[2].Name != "app" || sets[2].Values[0] != "203.0.113.5" || sets[2].TTL != 300 {
		t.Fatalf("stored sets = %+v", sets)
	}
	// Apex uses "@".
	apex, err := p.CreateRecord(zone, "example.com", "203.0.113.5", "A", 600)
	if err != nil || apex.ID != "@/A" {
		t.Fatalf("apex create = %+v, %v", apex, err)
	}
	// A duplicate set is refused with guidance, not silently replaced.
	if _, err := p.CreateRecord(zone, "app.example.com", "203.0.113.6", "A", 600); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate should be refused, got %v", err)
	}
	// Delete by composite ID removes the set; deleting again is fine.
	if err := p.DeleteRecord(zone, "app/A"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteRecord(zone, "app/A"); err != nil {
		t.Fatalf("second delete should be a no-op, got %v", err)
	}
	if err := p.DeleteRecord(zone, "malformed"); err == nil {
		t.Error("malformed id must be rejected")
	}
	if _, err := p.CreateRecord(zone, "app.example.com", "203.0.113.6", "A", 600); err != nil {
		t.Fatalf("create after delete: %v", err)
	}
	if fake.auth != "Bearer pat-secret" {
		t.Errorf("auth header = %q", fake.auth)
	}

	// Bad token → the API's message is surfaced.
	bad := &gandiProvider{token: "wrong", apiBase: p.apiBase, httpClient: p.httpClient}
	if _, err := bad.Ping(); err == nil || !strings.Contains(err.Error(), "Authorization failed") {
		t.Fatalf("bad token error = %v", err)
	}
}
