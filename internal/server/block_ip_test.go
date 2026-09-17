package server

import "testing"

func TestNormalizeBlockCIDR(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"203.0.113.5", "203.0.113.5/32", true},
		{"  203.0.113.5  ", "203.0.113.5/32", true},
		{"203.0.113.0/24", "203.0.113.0/24", true},
		{"2001:db8::1", "2001:db8::1/128", true},
		{"2001:db8::/48", "2001:db8::/48", true},
		{"", "", false},
		{"not-an-ip", "", false},
		{"999.999.999.999", "", false},
	}
	for _, tc := range tests {
		got, ok := normalizeBlockCIDR(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("normalizeBlockCIDR(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestMergeCIDRList(t *testing.T) {
	if got := mergeCIDRList("", "203.0.113.5/32"); got != "203.0.113.5/32" {
		t.Fatalf("into empty = %q", got)
	}
	if got := mergeCIDRList("10.0.0.0/8", "203.0.113.5/32"); got != "10.0.0.0/8,203.0.113.5/32" {
		t.Fatalf("append = %q", got)
	}
	// De-dupe: adding an existing entry is a no-op.
	if got := mergeCIDRList("10.0.0.0/8, 203.0.113.5/32", "203.0.113.5/32"); got != "10.0.0.0/8,203.0.113.5/32" {
		t.Fatalf("dedupe = %q", got)
	}
	// Blanks are dropped and whitespace trimmed.
	if got := mergeCIDRList(" 10.0.0.0/8 , , ", "203.0.113.5/32"); got != "10.0.0.0/8,203.0.113.5/32" {
		t.Fatalf("cleanup = %q", got)
	}
}
