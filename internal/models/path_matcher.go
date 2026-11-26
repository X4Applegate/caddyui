// SPDX-License-Identifier: Apache-2.0

package models

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"unicode"
	"unicode/utf8"
)

// Path matcher problems reported by PathMatcherProblem.
const (
	PathMatcherOK          = ""
	PathMatcherHasControl  = "control"
	PathMatcherBadRegexp   = "regexp"
	PathMatcherBadEncoding = "encoding"
)

// ErrInvalidPathMatcher is returned by CreateProxyHost and UpdateProxyHost
// when the host's Path matcher fails PathMatcherProblem.
var ErrInvalidPathMatcher = errors.New("invalid path matcher")

// PathMatcherProblem checks a proxy host's Path matcher (issue #184 review):
// it must be valid UTF-8 without control characters or Unicode line
// separators — a path never contains them, and they let the value break out
// of a Caddyfile token — and a "regexp" matcher must compile with Go's RE2,
// as Caddy would refuse it anyway. Returns PathMatcherOK or the problem.
func PathMatcherProblem(matcher, matcherType string) string {
	if matcher == "" {
		return PathMatcherOK
	}
	if !utf8.ValidString(matcher) {
		return PathMatcherBadEncoding
	}
	for _, r := range matcher {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return PathMatcherHasControl
		}
	}
	if matcherType == "regexp" {
		if _, err := regexp.Compile(matcher); err != nil {
			return PathMatcherBadRegexp
		}
	}
	return PathMatcherOK
}

// validatePathMatcher is the storage-level backstop for every entry path
// (form, JSON import, clone, fleet copy).
func validatePathMatcher(p *ProxyHost) error {
	if why := PathMatcherProblem(p.PathMatcher, p.PathMatcherType); why != PathMatcherOK {
		return fmt.Errorf("%w (%s)", ErrInvalidPathMatcher, why)
	}
	return nil
}

// pathMatcherUnchanged reports whether p's stored Path matcher and type are
// what p still holds. UpdateProxyHost lets such a row through even when it
// fails PathMatcherProblem: rows saved before that check existed must still
// be enabled, disabled, put in maintenance or given a certificate (those
// paths rewrite the whole row). The edit form refuses them with its own
// translated message, and the Caddyfile export fails closed on them.
func pathMatcherUnchanged(db *sql.DB, p *ProxyHost) bool {
	var matcher, typ string
	err := db.QueryRow(`SELECT COALESCE(path_matcher,''), COALESCE(path_matcher_type,'') FROM proxy_hosts WHERE id=?`, p.ID).Scan(&matcher, &typ)
	return err == nil && matcher == p.PathMatcher && typ == p.PathMatcherType
}
