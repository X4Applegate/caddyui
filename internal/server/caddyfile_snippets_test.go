// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/X4Applegate/caddyui/internal/caddy"
	"github.com/X4Applegate/caddyui/internal/models"
)

// Issue #119: CADDYFILE_PATH snippets were auto-loaded for Advanced routes and
// the Caddyfile paste importer, but not for a proxy host's Advanced config, so
// `import my_snippet` there was rejected with "File to import not found".

var (
	snippetImportRe = regexp.MustCompile(`(?m)^\s*import\s+(\S+)`)
	snippetDefRe    = regexp.MustCompile(`(?m)^\(([^)\s]+)\)\s*\{`)
)

// snippetAwareAdapter stands in for Caddy's /adapt endpoint: like the real
// adapter it rejects an `import <name>` whose snippet definition is not part
// of the submitted Caddyfile, and otherwise returns one adapted route. It
// records every Caddyfile it was asked to adapt.
func snippetAwareAdapter(t *testing.T) (*caddy.Client, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/adapt" {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()

		defined := map[string]bool{}
		for _, m := range snippetDefRe.FindAllStringSubmatch(body, -1) {
			defined[m[1]] = true
		}
		for _, m := range snippetImportRe.FindAllStringSubmatch(body, -1) {
			if !defined[m[1]] {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "adapting config using caddyfile adapter: File to import not found: " + m[1],
				})
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"result": map[string]any{"apps": map[string]any{"http": map[string]any{"servers": map[string]any{
				"srv0": map[string]any{
					"listen": []any{":443"},
					"routes": []any{map[string]any{"handle": []any{map[string]any{"handler": "headers"}}}},
				},
			}}}},
		})
	}))
	t.Cleanup(srv.Close)
	return caddy.New(srv.URL, "", ""), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

func writeTestCaddyfile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const mountedCaddyfile = `{
	email admin@example.com
}

(my_snippet) {
	header X-From-Snippet "yes"
}

(other) {
	encode gzip
}

example.com {
	respond "hi"
}
`

func TestProxyAdvancedConfigImportsSnippetFromCaddyfilePath(t *testing.T) {
	cl, bodies := snippetAwareAdapter(t)
	s := &Server{CaddyfilePath: writeTestCaddyfile(t, mountedCaddyfile)}

	if _, _, err := s.adaptProxyAdvancedWithClient(cl, models.ProxyHost{AdvancedConfig: "import my_snippet"}); err != nil {
		t.Fatalf("Advanced config importing a CADDYFILE_PATH snippet was rejected: %v", err)
	}

	sent := bodies()
	if len(sent) != 1 {
		t.Fatalf("adapt called %d times, want 1", len(sent))
	}
	body := sent[0]
	def, site := strings.Index(body, "(my_snippet) {"), strings.Index(body, "localhost {")
	if def < 0 || site < 0 || def > site {
		t.Fatalf("snippet definition must precede the synthetic site block:\n%s", body)
	}
	// Only snippets are borrowed from the mounted file — never its global
	// options or site blocks, which would clash with / duplicate live config.
	for _, leaked := range []string{"email admin@example.com", "example.com {", `respond "hi"`} {
		if strings.Contains(body, leaked) {
			t.Fatalf("non-snippet content %q leaked from CADDYFILE_PATH into the adapt request:\n%s", leaked, body)
		}
	}
}

func TestProxyAdvancedConfigImportFailsClearlyWithoutASnippetFile(t *testing.T) {
	for name, path := range map[string]string{
		"unset":      "",
		"missing":    filepath.Join(t.TempDir(), "does-not-exist"),
		"no snippet": writeTestCaddyfile(t, "example.com {\n\trespond \"hi\"\n}\n"),
	} {
		t.Run(name, func(t *testing.T) {
			cl, _ := snippetAwareAdapter(t)
			s := &Server{CaddyfilePath: path}
			_, _, err := s.adaptProxyAdvancedWithClient(cl, models.ProxyHost{AdvancedConfig: "import my_snippet"})
			if err == nil || !strings.Contains(err.Error(), "File to import not found: my_snippet") {
				t.Fatalf("err = %v, want Caddy's File-to-import-not-found error passed through", err)
			}
		})
	}
}

func TestProxyAdvancedConfigWithoutImportIsUnaffectedBySnippets(t *testing.T) {
	cl, _ := snippetAwareAdapter(t)
	s := &Server{CaddyfilePath: writeTestCaddyfile(t, mountedCaddyfile)}
	if _, _, err := s.adaptProxyAdvancedWithClient(cl, models.ProxyHost{AdvancedConfig: "header X-Plain yes"}); err != nil {
		t.Fatalf("plain Advanced config broke when snippets are present: %v", err)
	}
}

func TestWithAutoLoadedSnippetsSkipsSnippetsTheSourceRedefines(t *testing.T) {
	s := &Server{CaddyfilePath: writeTestCaddyfile(t, mountedCaddyfile)}
	src := "(my_snippet) {\n\theader X-Mine \"1\"\n}\n\nsite.example {\n\timport my_snippet\n\timport other\n}\n"
	got := s.withAutoLoadedSnippets(src)

	if n := strings.Count(got, "(my_snippet) {"); n != 1 {
		t.Fatalf("(my_snippet) defined %d times, want exactly 1 (Caddy rejects duplicates):\n%s", n, got)
	}
	if !strings.Contains(got, "X-Mine") || strings.Contains(got, "X-From-Snippet") {
		t.Fatalf("the source's own definition must win over the mounted file's:\n%s", got)
	}
	if !strings.Contains(got, "(other) {") {
		t.Fatalf("snippet the source did not define should have been loaded:\n%s", got)
	}
}

func TestWithAutoLoadedSnippetsLeavesSourceAloneWhenThereIsNothingToLoad(t *testing.T) {
	const src = "localhost {\n\theader X-A 1\n}\n"
	for name, s := range map[string]*Server{
		"unset path":  {},
		"missing":     {CaddyfilePath: filepath.Join(t.TempDir(), "nope")},
		"no snippets": {CaddyfilePath: writeTestCaddyfile(t, "example.com {\n\trespond \"hi\"\n}\n")},
	} {
		if got := s.withAutoLoadedSnippets(src); got != src {
			t.Fatalf("%s: source was modified: %q", name, got)
		}
	}
}

// The paths that already loaded snippets before #119 now share the helper;
// pin that they still do.
func TestAdvancedRouteCaddyfileStillLoadsSnippets(t *testing.T) {
	cl, bodies := snippetAwareAdapter(t)
	s := &Server{CaddyfilePath: writeTestCaddyfile(t, mountedCaddyfile)}

	if _, _, err := s.adaptRawRouteCaddyfile(cl, "site.example {\n\timport my_snippet\n}\n"); err != nil {
		t.Fatalf("Advanced route importing a CADDYFILE_PATH snippet was rejected: %v", err)
	}
	if sent := bodies(); len(sent) != 1 || !strings.Contains(sent[0], "(my_snippet) {") {
		t.Fatalf("snippet definition missing from the adapt request: %#v", sent)
	}
}
