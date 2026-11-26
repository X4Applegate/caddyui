// SPDX-License-Identifier: Apache-2.0

package models

import (
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
