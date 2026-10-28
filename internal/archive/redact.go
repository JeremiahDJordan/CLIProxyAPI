package archive

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Redacted replaces every credential value (redaction_version 1). It is a
// fixed marker; unlike HideAPIKey it keeps no characters of the secret.
const Redacted = "[redacted]"

// credentialHeaders are replaced entirely (lower-case names). The design's
// list, plus X-Management-Key, the proxy's own management credential.
var credentialHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"x-api-key":           {},
	"x-goog-api-key":      {},
	"cookie":              {},
	"set-cookie":          {},
	"x-management-key":    {},
}

// websocketKeyProtocolPrefix marks a Sec-WebSocket-Protocol entry that
// carries an API key (forwarded upstream by live/websocket.go).
const websocketKeyProtocolPrefix = "openai-insecure-api-key."

// RedactHeaders copies h with credential values replaced by Redacted.
func RedactHeaders(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for name, values := range h {
		lower := strings.ToLower(name)
		switch {
		case isCredentialHeader(lower):
			redacted := make([]string, len(values))
			for i := range redacted {
				redacted[i] = Redacted
			}
			out[name] = redacted
		case lower == "sec-websocket-protocol":
			out[name] = redactWebsocketProtocols(values)
		default:
			out[name] = slices.Clone(values)
		}
	}
	return out
}

func isCredentialHeader(lower string) bool {
	_, ok := credentialHeaders[lower]
	return ok
}

func redactWebsocketProtocols(values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		entries := strings.Split(value, ",")
		for j, entry := range entries {
			trimmed := strings.TrimSpace(entry)
			if strings.HasPrefix(strings.ToLower(trimmed), websocketKeyProtocolPrefix) {
				entries[j] = Redacted
			} else {
				entries[j] = trimmed
			}
		}
		out[i] = strings.Join(entries, ", ")
	}
	return out
}

// QueryRule validates the value of an allowed query parameter.
type QueryRule func(value string) bool

// QueryAllowlist maps an inference route's allowed parameters to their rule.
type QueryAllowlist map[string]QueryRule

var (
	safeQueryName = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_.$\-\[\]]{0,31}$`)
	versionValue  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)
	modelValue    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)
)

// BoolValue accepts true or false.
func BoolValue(value string) bool { return value == "true" || value == "false" }

// VersionValue accepts a client version such as 0.50.0 or 1.2.3-beta.1.
func VersionValue(value string) bool { return versionValue.MatchString(value) }

// ModelValue accepts a model identifier.
func ModelValue(value string) bool { return modelValue.MatchString(value) }

// EnumValue accepts exactly one of values.
func EnumValue(values ...string) QueryRule {
	return func(value string) bool { return slices.Contains(values, value) }
}

// UintValue accepts a decimal number of at most maxDigits digits.
func UintValue(maxDigits int) QueryRule {
	return func(value string) bool {
		if value == "" || len(value) > maxDigits {
			return false
		}
		for i := 0; i < len(value); i++ {
			if value[i] < '0' || value[i] > '9' {
				return false
			}
		}
		return true
	}
}

// RedactQuery keeps the values of allowed parameters that pass their rule
// and replaces every other value with Redacted. Names that do not look like
// parameter names, and bare tokens without '=', are redacted too.
func RedactQuery(rawQuery string, allow QueryAllowlist) string {
	if rawQuery == "" {
		return ""
	}
	parts := strings.Split(rawQuery, "&")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		rawName, rawValue, hasValue := strings.Cut(part, "=")
		name, errName := url.QueryUnescape(rawName)
		rule, allowed := allow[name]
		if errName != nil || !safeQueryName.MatchString(name) {
			out = append(out, Redacted)
			continue
		}
		if !hasValue {
			if allowed && rule("") {
				out = append(out, name)
			} else {
				out = append(out, Redacted)
			}
			continue
		}
		value, errValue := url.QueryUnescape(rawValue)
		if allowed && errValue == nil && rule(value) {
			out = append(out, name+"="+url.QueryEscape(value))
			continue
		}
		out = append(out, name+"="+Redacted)
	}
	return strings.Join(out, "&")
}

// QueryNames returns parameter names only, for metadata-only routes. Names
// that do not look like parameter names, and bare tokens, become Redacted.
func QueryNames(rawQuery string) []string {
	if rawQuery == "" {
		return nil
	}
	parts := strings.Split(rawQuery, "&")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		rawName, _, hasValue := strings.Cut(part, "=")
		name, err := url.QueryUnescape(rawName)
		if err != nil || !hasValue || !safeQueryName.MatchString(name) {
			out = append(out, Redacted)
			continue
		}
		out = append(out, name)
	}
	return out
}
