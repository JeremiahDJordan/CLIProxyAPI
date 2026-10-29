package archive

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/tidwall/gjson"
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

// credentialNameParts redact any header whose lower-case name contains one
// of them, so credentials under names nobody listed are covered too.
var credentialNameParts = []string{"key", "token", "secret", "password", "auth", "cookie", "session", "signature"}

// keptHeaders are not credentials although their names match a part above
// (or might one day). Session IDs are needed for joins (design section 5).
var keptHeaders = map[string]struct{}{
	"anthropic-beta":           {},
	"x-codex-turn-metadata":    {},
	"session_id":               {},
	"session-id":               {},
	"x-session-id":             {},
	"x-parent-session-id":      {},
	"x-claude-code-session-id": {},
}

// urlHeaders carry URLs whose query and fragment are redacted like a route
// query without an allowlist (an OAuth redirect's code and state, say).
var urlHeaders = map[string]struct{}{
	"referer":          {},
	"origin":           {},
	"location":         {},
	"content-location": {},
	"link":             {},
	"x-forwarded-uri":  {},
	"x-original-uri":   {},
	"x-original-url":   {},
	"x-rewrite-url":    {},
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
		case isURLHeader(lower):
			redacted := make([]string, len(values))
			for i, value := range values {
				if lower == "link" {
					redacted[i] = redactLinkValue(value)
				} else {
					redacted[i] = RedactURL(value)
				}
			}
			out[name] = redacted
		default:
			out[name] = slices.Clone(values)
		}
	}
	return out
}

func isCredentialHeader(lower string) bool {
	if _, ok := credentialHeaders[lower]; ok {
		return true
	}
	if _, ok := keptHeaders[lower]; ok {
		return false
	}
	for _, part := range credentialNameParts {
		if !strings.Contains(lower, part) {
			continue
		}
		// A rate-limit count header's one "tokens" is a count, not a token.
		if part == "token" && strings.Count(lower, part) == 1 && rateLimitTokenCount.MatchString(lower) {
			continue
		}
		return true
	}
	return false
}

// rateLimitTokenCount matches the token-count rate-limit headers: OpenAI's
// x-ratelimit-{limit,remaining,reset}-tokens, Anthropic's
// anthropic-ratelimit-{,input-,output-}tokens-{limit,remaining,reset} and the
// per-window variants (x-ratelimit-remaining-tokens-minute). It exempts only
// the "token" part; every other credential part still redacts the header.
var rateLimitTokenCount = regexp.MustCompile(`(^|[-_])ratelimit-((limit|remaining|reset)-)?((input|output)-)?tokens(-(limit|remaining|reset))?(-(second|minute|hour|day))?$`)

func isURLHeader(lower string) bool {
	_, ok := urlHeaders[lower]
	return ok
}

// RedactURL keeps a URL's scheme, host and path. Every query and fragment
// value becomes Redacted, as for a route query without an allowlist, and
// user information is dropped. A value that does not parse is Redacted.
func RedactURL(value string) string {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Opaque != "" {
		return Redacted
	}
	u.User = nil
	u.RawQuery = RedactQuery(u.RawQuery, nil)
	fragment := u.EscapedFragment()
	u.Fragment, u.RawFragment = "", ""
	out := u.String()
	if fragment != "" {
		out += "#" + RedactQuery(fragment, nil)
	}
	return out
}

var linkTarget = regexp.MustCompile(`<[^>]*>`)

// redactLinkValue redacts the URL in each <target> of a Link header.
func redactLinkValue(value string) string {
	return linkTarget.ReplaceAllStringFunc(value, func(target string) string {
		return "<" + RedactURL(target[1:len(target)-1]) + ">"
	})
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
	// A version is up to four numbers with short dotted pre-release or
	// build parts: 0.50.0, v1.2, 1.2.3-beta.1, 0.46.0-alpha.3+build.7.
	versionValue = regexp.MustCompile(`^v?[0-9]{1,9}(\.[0-9]{1,9}){0,3}([-+][0-9A-Za-z]{1,12}(\.[0-9A-Za-z]{1,12}){0,3}){0,2}$`)
	// A model is lower-case words, numbers and dates joined by - . _ : / @:
	// gpt-realtime, gemini-2.0-flash-live-001, claude-sonnet-4-5@20250929.
	modelValue = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/@-]{0,63}$`)
	// longRun finds an unbroken alphanumeric run as long as a key's body.
	longRun = regexp.MustCompile(`[A-Za-z0-9]{17,}`)
)

// keyPrefixes start common credentials (compared in lower case).
var keyPrefixes = []string{"sk-", "sk_", "rk_", "pk_", "aiza", "ya29.", "ghp_", "gho_", "github_pat_", "glpat-", "xox", "akia"}

// looksLikeKey reports a value shaped like a credential rather than a name:
// a known key prefix or a long unbroken run of letters and digits.
func looksLikeKey(value string) bool {
	lower := strings.ToLower(value)
	for _, prefix := range keyPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return longRun.MatchString(value)
}

// BoolValue accepts true or false.
func BoolValue(value string) bool { return value == "true" || value == "false" }

// VersionValue accepts a client version such as 0.50.0 or 1.2.3-beta.1.
func VersionValue(value string) bool { return len(value) <= 64 && versionValue.MatchString(value) }

// ModelValue accepts a model identifier and rejects anything shaped like a key.
func ModelValue(value string) bool { return modelValue.MatchString(value) && !looksLikeKey(value) }

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
		if errName != nil || !isQueryName(name) {
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
		if err != nil || !hasValue || !isQueryName(name) {
			out = append(out, Redacted)
			continue
		}
		out = append(out, name)
	}
	return out
}

// isQueryName reports a parameter name that is safe to keep: shaped like a
// name and not like a key (a key sent as a bare name, ?sk-...=1).
func isQueryName(name string) bool {
	return safeQueryName.MatchString(name) && !looksLikeKey(name)
}

// upstreamQuery is the typed allowlist for outbound request URLs: values
// that select a response format or API version. Every other value (a
// ?key= API key, say) is redacted.
var upstreamQuery = QueryAllowlist{
	"alt":            EnumValue("sse", "json", "proto"),
	"$alt":           EnumValue("sse", "json", "proto"),
	"beta":           BoolValue,
	"client_version": VersionValue,
	"model":          ModelValue,
	"api-version":    func(value string) bool { return apiVersionValue.MatchString(value) },
}

var apiVersionValue = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}(-preview)?$|^v[0-9]{1,2}(beta|alpha)?[0-9]?$`)

// RedactUpstreamURL keeps an outbound URL's scheme, host and path and the
// values of the upstream allowlist; other query values, the fragment and user
// information are redacted or dropped. A value that does not parse is Redacted.
func RedactUpstreamURL(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Opaque != "" {
		return Redacted
	}
	u.User = nil
	u.RawQuery = RedactQuery(u.RawQuery, upstreamQuery)
	u.Fragment, u.RawFragment = "", ""
	return u.String()
}

var (
	textURL    = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://[^\s"'<>` + "`" + `]+`)
	textScheme = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=\-]{4,}`)
	// A name that suggests a credential, an assignment and its value.
	textPair  = regexp.MustCompile(`(?i)([A-Za-z0-9_.\-]*(?:key|token|secret|password|passwd|signature|credential|cookie)[A-Za-z0-9_.\-]*)(["']?\s*[:=]\s*["']?)([^\s"'&,;}\[\])]+)`)
	textShape = regexp.MustCompile(`\b(?:sk-|sk_|rk_|pk_|AIza|ya29\.|ghp_|gho_|github_pat_|glpat-|xox[a-z]-|AKIA)[A-Za-z0-9._\-]{6,}`)
	allDigits = regexp.MustCompile(`^[0-9]+$`)
)

// RedactText redacts credentials in free text such as error messages: URLs
// get RedactURL, authorization schemes, values assigned to credential-like
// names (except plain numbers, such as a token count) and key-shaped words
// become Redacted.
func RedactText(s string) string {
	if s == "" {
		return ""
	}
	s = textURL.ReplaceAllStringFunc(s, RedactURL)
	s = textScheme.ReplaceAllString(s, "${1} "+Redacted)
	s = textPair.ReplaceAllStringFunc(s, func(match string) string {
		parts := textPair.FindStringSubmatch(match)
		if allDigits.MatchString(parts[3]) || parts[3] == Redacted {
			return match
		}
		return parts[1] + parts[2] + Redacted
	})
	return textShape.ReplaceAllString(s, Redacted)
}

// RedactJSON copies a JSON value for metadata (a provider's usage object),
// with credentials redacted by the rules above; bodies are never redacted.
// Every string under a member whose name is a credential name
// (credentialField) becomes Redacted, while numbers, booleans and nulls are
// kept (a token count is a number). Any other string becomes Redacted when
// it looks like a key and is otherwise passed through RedactText. Members
// keep their order and numbers their text. Input that is not JSON is null.
func RedactJSON[R []byte | string](raw R) []byte {
	text := string(raw)
	if !gjson.Valid(text) {
		return []byte("null")
	}
	value := gjson.Parse(text)
	return redactJSONValue(make([]byte, 0, len(value.Raw)), value, false)
}

func redactJSONValue(out []byte, value gjson.Result, credential bool) []byte {
	switch {
	case value.IsObject(), value.IsArray():
		object := value.IsObject()
		open, end := byte('['), byte(']')
		if object {
			open, end = '{', '}'
		}
		out = append(out, open)
		first := true
		value.ForEach(func(key, member gjson.Result) bool {
			if !first {
				out = append(out, ',')
			}
			first = false
			memberCredential := credential
			if object {
				// key.Raw is not always the member name as written; encode it.
				name, _ := marshalCompact(key.String())
				out = append(out, name...)
				out = append(out, ':')
				memberCredential = credential || credentialField(key.String())
			}
			out = redactJSONValue(out, member, memberCredential)
			return true
		})
		return append(out, end)
	case value.Type == gjson.String:
		text := value.String()
		if credential || looksLikeKey(text) {
			return append(out, `"`+Redacted+`"`...)
		}
		if redacted := RedactText(text); redacted != text {
			if encoded, err := marshalCompact(redacted); err == nil {
				return append(out, encoded...)
			}
			return append(out, `"`+Redacted+`"`...)
		}
		return append(out, value.Raw...)
	default:
		return append(out, value.Raw...)
	}
}

// credentialField reports a JSON member name that names a credential: a
// credential header name, or a name containing a credential part, as for
// headers. A token count is not a credential, so "token" counts only where
// it is neither part of "tokens" nor followed by "count" (input_tokens,
// promptTokenCount and prompt_tokens_details are counts; access_token,
// id_token and token_breakdown are not exempt).
func credentialField(name string) bool {
	lower := strings.ToLower(name)
	if _, ok := credentialHeaders[lower]; ok {
		return true
	}
	for _, part := range credentialNameParts {
		if part == "token" {
			if credentialToken(lower) {
				return true
			}
			continue
		}
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

func credentialToken(lower string) bool {
	for rest := lower; ; {
		i := strings.Index(rest, "token")
		if i < 0 {
			return false
		}
		rest = rest[i+len("token"):]
		if strings.HasPrefix(rest, "s") || strings.HasPrefix(strings.TrimLeft(rest, "_-"), "count") {
			continue
		}
		return true
	}
}
