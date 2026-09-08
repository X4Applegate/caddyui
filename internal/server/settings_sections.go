package server

import (
	"encoding/json"
	"html/template"
	"strings"
)

// v2.44.0: Settings is split into pages, one per area, instead of one form
// with sixteen cards. Each page posts only its own fields, so the save
// handler must only write the keys that page owns — otherwise saving
// "General" would blank the SMTP host, the analytics target and every
// other value the page did not render. settingsKeySection is that
// ownership table; postSettings drops every key the posted page does not
// own. Dynamic keys (DNS provider credentials, fleet integration settings)
// are gated at collection time instead.

type settingsSection struct {
	Slug  string
	Label string
	Blurb string
}

// settingsSections is the navigation, in order. Slugs are URL segments.
var settingsSections = []settingsSection{
	{"general", "General", "Site title, maintenance, auto-sync, timezone, post-apply checks"},
	{"notifications", "Notifications", "Email (SMTP), webhook, ntfy, certificate alerts"},
	{"dns", "DNS", "Public IPs, provider credentials, zones"},
	{"security", "Security", "2FA policy, sessions, allowlists, CAPTCHA"},
	{"analytics", "Analytics", "Visitor analytics, retention, storage"},
	{"integrations", "Integrations", "Caddy access logs, Prometheus metrics, CrowdSec"},
	{"ai", "AI assistant", "Provider, model, system prompt"},
	{"backup", "Backup", "Database backup"},
}

const defaultSettingsSection = "general"

// settingsSectionSlug validates a slug from the URL or the form: "" for
// unknown, so callers can 404 or fall back.
func settingsSectionSlug(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	for _, sec := range settingsSections {
		if sec.Slug == raw {
			return raw
		}
	}
	return ""
}

func settingsSectionLabel(slug string) string {
	for _, sec := range settingsSections {
		if sec.Slug == slug {
			return sec.Label
		}
	}
	return "Settings"
}

// settingsAnchorSection maps the pre-v2.44.0 in-page anchors to the page
// that now holds the card, for old links and bookmarks.
var settingsAnchorSection = map[string]string{
	"settings-general":       "general",
	"settings-timezone":      "general",
	"expectations":           "general",
	"settings-smtp":          "notifications",
	"settings-notifications": "notifications",
	"settings-notifier":      "notifications",
	"settings-dns":           "dns",
	"settings-dns-ips":       "dns",
	"settings-dns-providers": "dns",
	"settings-captcha":       "security",
	"settings-security":      "security",
	"settings-ai":            "ai",
	"settings-access-logs":   "integrations",
	"settings-metrics":       "integrations",
	"settings-crowdsec":      "integrations",
	"analytics":              "analytics",
	"settings-backup":        "backup",
}

// settingsKeySection is which page owns each setting key the save handler
// can write. A key missing here is written on every page — keep it
// complete (TestSettingsSectionsOwnEveryStaticKey checks the handler).
var settingsKeySection = map[string]string{
	settingSiteTitle:                  "general",
	settingFaviconURL:                 "general",
	settingCatchAll404HTML:            "general",
	settingGlobalMaintenance:          "general",
	settingAutoSyncHours:              "general",
	settingActivityLogDays:            "general",
	settingGlobalStripResponseHeaders: "general",
	settingTimezone:                   "general",
	settingExpectationsAutoRollback:   "general",

	settingNotifyWebhookURL:    "notifications",
	settingNotifyWebhookSecret: "notifications",
	settingNotifyNtfyURL:       "notifications",
	settingNotifyNtfyToken:     "notifications",
	settingNotifyDaysBefore:    "notifications",
	settingSMTPHost:            "notifications",
	settingSMTPPort:            "notifications",
	settingSMTPUsername:        "notifications",
	settingSMTPPassword:        "notifications",
	settingSMTPFrom:            "notifications",
	settingSMTPTo:              "notifications",
	settingSMTPSecurity:        "notifications",
	settingSMTPSkipVerify:      "notifications",

	settingServerIP:  "dns",
	settingCFProxied: "dns",

	settingRequire2FA:         "security",
	settingRequireTOTP:        "security",
	settingTrustedProxies:     "security",
	settingClientIPHeaders:    "security",
	settingDisableHTTP3:       "security",
	settingAdminAllowlist:     "security",
	settingSessionDays:        "security",
	settingMaxLoginAttempts:   "security",
	settingCaptchaProvider:    "security",
	settingTurnstileSiteKey:   "security",
	settingTurnstileSecretKey: "security",
	settingRecaptchaSiteKey:   "security",
	settingRecaptchaSecretKey: "security",
	settingRecaptchaMinScore:  "security",

	settingAnalyticsEnabled:        "analytics",
	settingAnalyticsIngestTarget:   "analytics",
	settingAnalyticsExcludeIPs:     "analytics",
	settingAnalyticsSoftStart:      "analytics",
	settingAnalyticsDialTimeoutSec: "analytics",
	settingAnalyticsRetentionDays:  "analytics",

	settingCrowdSecAPIKey: "integrations",

	settingAIEnabled:           "ai",
	settingAIProvider:          "ai",
	settingAIOllamaURL:         "ai",
	settingAIOllamaModel:       "ai",
	settingAIOllamaCloudModel:  "ai",
	settingAIOllamaCloudAPIKey: "ai",
	settingAIAnthropicModel:    "ai",
	settingAIAnthropicAPIKey:   "ai",
	settingAIOpenAIBaseURL:     "ai",
	settingAIOpenAIModel:       "ai",
	settingAIOpenAIAPIKey:      "ai",
	settingAISystemPrompt:      "ai",
}

// settingsSectionSyncsCaddy reports whether saving a page can change the
// live Caddy config and therefore warrants the auto-sync that follows a
// save. Notification, AI and backup settings never reach Caddy.
func settingsSectionSyncsCaddy(slug string) bool {
	switch slug {
	case "notifications", "ai", "backup":
		return false
	}
	return true
}

// settingsAnchorsJSON is settingsAnchorSection for the page's redirect script.
func settingsAnchorsJSON() template.JS {
	raw, err := json.Marshal(settingsAnchorSection)
	if err != nil {
		return template.JS("{}")
	}
	return template.JS(raw) // nolint:gosec // fixed table of slugs, no user input
}
