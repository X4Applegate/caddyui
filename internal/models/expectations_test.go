package models

import (
	"reflect"
	"testing"
)

// v2.38.0: post-apply expectations — canonical form, description, parsing.
func TestHostExpectationNormalizedAndDescribe(t *testing.T) {
	got := HostExpectation{Method: "post", Scheme: "HTTP", Path: "healthz", ExpectStatus: 999, MaxLatencyMS: -5, ExpectLocation: " https://x/ ", Label: " api "}.Normalized()
	want := HostExpectation{Method: "POST", Scheme: "http", Path: "/healthz", ExpectStatus: 0, MaxLatencyMS: 0, ExpectLocation: "https://x/", Label: "api"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalized = %+v, want %+v", got, want)
	}
	if got := (HostExpectation{Method: "TRACE"}).Normalized().Method; got != "GET" {
		t.Errorf("unknown method normalised to %q, want GET", got)
	}
	d := HostExpectation{Method: "GET", Scheme: "https", Path: "/healthz", ExpectStatus: 200, MaxLatencyMS: 500, VerifyTLS: true}.Describe()
	if d != "GET https /healthz → 200 (≤ 500 ms) [valid TLS]" {
		t.Errorf("Describe = %q", d)
	}
	if d := (HostExpectation{Scheme: "http", ExpectStatus: 308, ExpectLocation: "https://"}).Describe(); d != "GET http / → 308 to https://" {
		t.Errorf("Describe (redirect) = %q", d)
	}
}

func TestParseAndNormalizeHostExpectations(t *testing.T) {
	for _, raw := range []string{"", "  ", "[]", "not json", `{"method":"GET"}`} {
		if got := ParseHostExpectations(raw); got != nil {
			t.Errorf("ParseHostExpectations(%q) = %+v, want nil", raw, got)
		}
	}
	raw := `[{"method":"get","scheme":"https","path":"healthz","expect_status":200,"junk":1},{"method":"GET","scheme":"http","path":"/","expect_status":308,"expect_location":"https://","disabled":true}]`
	list := ParseHostExpectations(raw)
	if len(list) != 2 || list[0].Method != "GET" || list[0].Path != "/healthz" || !list[1].Disabled {
		t.Fatalf("ParseHostExpectations = %+v", list)
	}
	canon := NormalizeHostExpectationsJSON(raw)
	if canon == "" || canon == raw {
		t.Fatalf("NormalizeHostExpectationsJSON should re-encode canonically, got %q", canon)
	}
	if again := NormalizeHostExpectationsJSON(canon); again != canon {
		t.Errorf("normalisation must be idempotent:\n%s\n%s", canon, again)
	}
	if NormalizeHostExpectationsJSON("[]") != "" || NormalizeHostExpectationsJSON("garbage") != "" {
		t.Error("empty or malformed input must store as empty")
	}
	p := ProxyHost{Expectations: canon}
	if got := p.ActiveExpectations(); len(got) != 1 || got[0].Path != "/healthz" {
		t.Errorf("ActiveExpectations should drop disabled entries, got %+v", got)
	}
}
