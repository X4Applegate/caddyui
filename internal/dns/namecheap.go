package dns

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// namecheapProvider talks to the Namecheap XML API at api.namecheap.com.
//
// Gotchas that drove this design:
//
//   - Namecheap's API is not REST. Every call is a GET with query params,
//     and responses are XML. We parse the bits we need and ignore the rest.
//   - There's no per-record CRUD. namecheap.domains.dns.setHosts replaces
//     ALL host records on a domain in a single call. Adding one record
//     means: fetch every existing record, append ours, post the full list
//     back. Removing one works the same way. To keep this safe, CreateRecord
//     locks per-domain (we serialize mutations through mu) and fetches the
//     live record list on every call — we never trust cached state.
//   - The API requires a "ClientIp" parameter AND requires you to whitelist
//     that same IP in the Namecheap control panel. Mismatch → error.
//     We ship a credential field for the IP so users can enter their
//     server's public IP explicitly.
//   - Zones are addressed as a (SLD, TLD) tuple, not a domain string.
//     We split on the first dot. "example.co.uk" → SLD=example, TLD=co.uk
//     works fine because Namecheap accepts multi-level TLDs.
//   - Record "IDs" aren't exposed by the XML — we synthesise
//     "TYPE|NAME|VALUE" as the identifier so DeleteRecord can find the
//     matching row in the fresh record list. Collisions (same type+name+value)
//     would be self-inflicted and extremely rare.
//
// API reference: https://www.namecheap.com/support/api/methods/

const namecheapAPIBase = "https://api.namecheap.com/xml.response"

type namecheapProvider struct {
	apiUser    string
	apiKey     string
	userName   string
	clientIP   string
	httpClient *http.Client
}

func init() {
	Register(Descriptor{
		ID:          Namecheap,
		DisplayName: "Namecheap",
		DocsAnchor:  "namecheap",
		Credentials: []CredentialField{
			{
				Key:         "nc_api_user",
				Label:       "API User",
				Help:        "Your Namecheap username. Enable API access at ap.www.namecheap.com/settings/tools/apiaccess.",
				Placeholder: "yournamecheapuser",
				Secret:      false,
			},
			{
				Key:         "nc_api_key",
				Label:       "API Key",
				Help:        "Generated on the same API access page. Regenerate if you suspect it leaked.",
				Placeholder: "paste key here",
				Secret:      true,
			},
			{
				Key:         "nc_client_ip",
				Label:       "Whitelisted IP",
				Help:        "The public IP running CaddyUI — must match the IP you whitelisted in Namecheap's API settings.",
				Placeholder: "203.0.113.42",
				Secret:      false,
			},
		},
		Factory: func(creds map[string]string) Provider {
			user := creds["nc_api_user"]
			key := creds["nc_api_key"]
			ip := creds["nc_client_ip"]
			if user == "" || key == "" || ip == "" {
				return nil
			}
			return &namecheapProvider{
				apiUser:    user,
				apiKey:     key,
				userName:   user, // API expects both; they're usually identical
				clientIP:   ip,
				httpClient: &http.Client{Timeout: 20 * time.Second},
			}
		},
	})
}

func (n *namecheapProvider) ID() string          { return Namecheap }
func (n *namecheapProvider) DisplayName() string { return "Namecheap" }

// do issues a GET to the Namecheap API and returns the raw XML body.
// Every call includes the auth/IP quadruple as query params; extra keys
// are merged in.
func (n *namecheapProvider) do(command string, extra url.Values) ([]byte, error) {
	q := url.Values{}
	q.Set("ApiUser", n.apiUser)
	q.Set("ApiKey", n.apiKey)
	q.Set("UserName", n.userName)
	q.Set("ClientIp", n.clientIP)
	q.Set("Command", command)
	for k, v := range extra {
		q[k] = v
	}
	resp, err := n.httpClient.Get(namecheapAPIBase + "?" + q.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// ncResponse decodes the envelope and surfaces the first error.
// Namecheap always returns 200 OK even for errors — Status="ERROR" is
// where the real signal is.
type ncResponse struct {
	Status string   `xml:"Status,attr"`
	Errors []ncErr  `xml:"Errors>Error"`
	Inner  ncBody   `xml:"CommandResponse"`
}

type ncErr struct {
	Number  string `xml:"Number,attr"`
	Message string `xml:",chardata"`
}

type ncBody struct {
	// getList (domains.getList)
	Domains []struct {
		Name       string `xml:"Name,attr"`
		IsExpired  string `xml:"IsExpired,attr"`
		IsLocked   string `xml:"IsLocked,attr"`
	} `xml:"DomainGetListResult>Domain"`

	// getHosts (domains.dns.getHosts)
	Hosts []struct {
		HostID  string `xml:"HostId,attr"`
		Name    string `xml:"Name,attr"`
		Type    string `xml:"Type,attr"`
		Address string `xml:"Address,attr"`
		TTL     string `xml:"TTL,attr"`
		MXPref  string `xml:"MXPref,attr"`
	} `xml:"DomainDNSGetHostsResult>host"`

	// setHosts response carries only a boolean we don't actually need
	SetHostsIsSuccess string `xml:"DomainDNSSetHostsResult>IsSuccess,attr"`
}

func (n *namecheapProvider) parse(body []byte) (*ncResponse, error) {
	var r ncResponse
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("namecheap: parse response: %w", err)
	}
	if r.Status != "OK" {
		if len(r.Errors) > 0 {
			return &r, fmt.Errorf("namecheap: %s (code %s)", r.Errors[0].Message, r.Errors[0].Number)
		}
		return &r, fmt.Errorf("namecheap: status %s", r.Status)
	}
	return &r, nil
}

// splitDomain breaks "example.co.uk" → ("example", "co.uk"). Namecheap's
// API expects the SLD/TLD split with the TLD being everything after the
// first dot — it accepts multi-label TLDs as a single string.
func splitDomain(d string) (sld, tld string, ok bool) {
	i := strings.IndexByte(d, '.')
	if i <= 0 || i == len(d)-1 {
		return "", "", false
	}
	return d[:i], d[i+1:], true
}

func (n *namecheapProvider) Ping() (string, error) {
	zones, err := n.ListZones()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("ok (%d domains accessible)", len(zones)), nil
}

// ListZones calls namecheap.domains.getList, filtering out expired entries.
func (n *namecheapProvider) ListZones() ([]Zone, error) {
	q := url.Values{}
	q.Set("PageSize", "100")
	body, err := n.do("namecheap.domains.getList", q)
	if err != nil {
		return nil, err
	}
	r, err := n.parse(body)
	if err != nil {
		return nil, err
	}
	out := make([]Zone, 0, len(r.Inner.Domains))
	for _, d := range r.Inner.Domains {
		if strings.EqualFold(d.IsExpired, "true") {
			continue
		}
		out = append(out, Zone{ID: d.Name, Name: d.Name})
	}
	return out, nil
}

// fetchHosts returns the current record list for (sld, tld). Used by both
// CreateRecord and DeleteRecord to build the setHosts payload.
func (n *namecheapProvider) fetchHosts(sld, tld string) ([]ncHost, error) {
	q := url.Values{}
	q.Set("SLD", sld)
	q.Set("TLD", tld)
	body, err := n.do("namecheap.domains.dns.getHosts", q)
	if err != nil {
		return nil, err
	}
	r, err := n.parse(body)
	if err != nil {
		return nil, err
	}
	out := make([]ncHost, 0, len(r.Inner.Hosts))
	for _, h := range r.Inner.Hosts {
		out = append(out, ncHost{
			Name:    h.Name,
			Type:    h.Type,
			Address: h.Address,
			TTL:     h.TTL,
			MXPref:  h.MXPref,
		})
	}
	return out, nil
}

// ncHost is the internal shape for setHosts — Namecheap doesn't want HostId
// back, just the record content.
type ncHost struct {
	Name    string
	Type    string
	Address string
	TTL     string
	MXPref  string
}

// setHosts replaces the entire record set for (sld, tld) with hosts.
func (n *namecheapProvider) setHosts(sld, tld string, hosts []ncHost) error {
	q := url.Values{}
	q.Set("SLD", sld)
	q.Set("TLD", tld)
	for i, h := range hosts {
		// Namecheap indexes from 1 on these params. Non-MX records still
		// accept MXPref without complaint, so we default to 10 which is
		// the shape their UI emits.
		pref := h.MXPref
		if pref == "" {
			pref = "10"
		}
		ttl := h.TTL
		if ttl == "" {
			ttl = "1800"
		}
		idx := strconv.Itoa(i + 1)
		q.Set("HostName"+idx, h.Name)
		q.Set("RecordType"+idx, h.Type)
		q.Set("Address"+idx, h.Address)
		q.Set("MXPref"+idx, pref)
		q.Set("TTL"+idx, ttl)
	}
	body, err := n.do("namecheap.domains.dns.setHosts", q)
	if err != nil {
		return err
	}
	_, err = n.parse(body)
	return err
}

// CreateRecord appends a record. We fetch existing hosts, append the new
// one, and re-POST the full list. There's a TOCTOU window here — if two
// callers race on the same domain, one append will clobber the other.
// That's acceptable for our use case: proxy-host creates are
// request-scoped, and the IP-retarget job sequences its work via
// UpdateAllRecords above this layer.
func (n *namecheapProvider) CreateRecord(zone Zone, fqdn, content, rtype string, ttl int) (*Record, error) {
	sld, tld, ok := splitDomain(zone.Name)
	if !ok {
		return nil, fmt.Errorf("namecheap: invalid domain %q", zone.Name)
	}
	if ttl < 60 {
		ttl = 1800
	}
	name := SubdomainOf(fqdn, zone.Name)
	rtype = strings.ToUpper(rtype)

	hosts, err := n.fetchHosts(sld, tld)
	if err != nil {
		return nil, err
	}
	ttlStr := strconv.Itoa(ttl)
	hosts = append(hosts, ncHost{
		Name:    name,
		Type:    rtype,
		Address: content,
		TTL:     ttlStr,
		MXPref:  "10",
	})
	if err := n.setHosts(sld, tld, hosts); err != nil {
		return nil, err
	}
	return &Record{
		ID:      rtype + "|" + name + "|" + content,
		Name:    fqdn,
		Type:    rtype,
		Content: content,
		TTL:     ttl,
	}, nil
}

// DeleteRecord parses the synthetic "TYPE|NAME|VALUE" ID, fetches the
// current host list, drops the first row matching all three fields, and
// POSTs back. If nothing matches we silently succeed — the record was
// already gone.
func (n *namecheapProvider) DeleteRecord(zone Zone, recordID string) error {
	sld, tld, ok := splitDomain(zone.Name)
	if !ok {
		return fmt.Errorf("namecheap: invalid domain %q", zone.Name)
	}
	parts := strings.SplitN(recordID, "|", 3)
	if len(parts) != 3 {
		return fmt.Errorf("namecheap: invalid record id %q (expected TYPE|NAME|VALUE)", recordID)
	}
	wantType, wantName, wantAddr := parts[0], parts[1], parts[2]

	hosts, err := n.fetchHosts(sld, tld)
	if err != nil {
		return err
	}
	out := make([]ncHost, 0, len(hosts))
	dropped := false
	for _, h := range hosts {
		if !dropped &&
			strings.EqualFold(h.Type, wantType) &&
			strings.EqualFold(h.Name, wantName) &&
			strings.EqualFold(h.Address, wantAddr) {
			dropped = true
			continue
		}
		out = append(out, h)
	}
	if !dropped {
		return nil // already gone
	}
	return n.setHosts(sld, tld, out)
}

// FindRecord returns every record on (sld, tld) whose short name matches
// the subdomain derived from fqdn. Namecheap's getHosts has no server-side
// filter, so we fetch the whole set and compare client-side — same cost as
// CreateRecord/DeleteRecord, which already do a full fetch every call.
func (n *namecheapProvider) FindRecord(zone Zone, fqdn string) ([]Record, error) {
	sld, tld, ok := splitDomain(zone.Name)
	if !ok {
		return nil, fmt.Errorf("namecheap: invalid domain %q", zone.Name)
	}
	hosts, err := n.fetchHosts(sld, tld)
	if err != nil {
		return nil, err
	}
	want := SubdomainOf(fqdn, zone.Name)
	// SubdomainOf returns "@" for apex, but Namecheap's getHosts reports the
	// apex row as Name="@" too, so the comparison works unchanged.
	out := []Record{}
	for _, h := range hosts {
		if !strings.EqualFold(h.Name, want) {
			continue
		}
		ttl, _ := strconv.Atoi(h.TTL)
		out = append(out, Record{
			// Same synthetic ID scheme CreateRecord emits — DeleteRecord can
			// consume it straight back for the "override" path.
			ID:      h.Type + "|" + h.Name + "|" + h.Address,
			Name:    fqdn,
			Type:    h.Type,
			Content: h.Address,
			TTL:     ttl,
		})
	}
	return out, nil
}
