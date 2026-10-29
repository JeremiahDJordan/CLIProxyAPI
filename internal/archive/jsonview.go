package archive

import (
	"strings"

	"github.com/tidwall/gjson"
)

// Bounded JSON reads for inspection outside the queue's reservations. gjson
// unescapes every string it returns, and every escaped member name it
// compares on the way, into a copy as large as the string (gjson.Get on an
// 8 MiB escaped ID allocates it twice over). These helpers read raw tokens
// of a view (BytesView) instead and copy nothing, except a short escaped
// string, whose unescaped copy is bounded.

// jsonGet returns the raw value at the object path keys in json, or "" when
// there is none: a view of json. Member names are matched as written, so a
// name written with escapes never matches. json need not be valid.
func jsonGet(json string, keys ...string) string {
	for _, key := range keys {
		if json = jsonMember(json, key); json == "" {
			return ""
		}
	}
	return json
}

// jsonMember returns the raw value of obj's first member named key.
func jsonMember(obj, key string) string {
	i := jsonSkipSpace(obj, 0)
	if i >= len(obj) || obj[i] != '{' {
		return ""
	}
	for i++; ; i++ {
		i = jsonSkipSpace(obj, i)
		if i >= len(obj) || obj[i] != '"' {
			return ""
		}
		nameEnd := jsonValueEnd(obj, i)
		if nameEnd < 0 {
			return ""
		}
		name := obj[i+1 : nameEnd-1]
		i = jsonSkipSpace(obj, nameEnd)
		if i >= len(obj) || obj[i] != ':' {
			return ""
		}
		i = jsonSkipSpace(obj, i+1)
		end := jsonValueEnd(obj, i)
		if end < 0 {
			return ""
		}
		if name == key {
			return obj[i:end]
		}
		if i = jsonSkipSpace(obj, end); i >= len(obj) || obj[i] != ',' {
			return ""
		}
	}
}

// jsonEach calls fn with the raw value of each element of the array arr,
// until fn returns false.
func jsonEach(arr string, fn func(elem string) bool) {
	i := jsonSkipSpace(arr, 0)
	if i >= len(arr) || arr[i] != '[' {
		return
	}
	if i = jsonSkipSpace(arr, i+1); i < len(arr) && arr[i] == ']' {
		return
	}
	for {
		end := jsonValueEnd(arr, i)
		if end < 0 || !fn(arr[i:end]) {
			return
		}
		if i = jsonSkipSpace(arr, end); i >= len(arr) || arr[i] != ',' {
			return
		}
		i = jsonSkipSpace(arr, i+1)
	}
}

func jsonSkipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	return i
}

// jsonValueEnd returns the end of the value that starts at s[i], or -1.
func jsonValueEnd(s string, i int) int {
	if i >= len(s) {
		return -1
	}
	switch s[i] {
	case '"':
		for j := i + 1; j < len(s); j++ {
			switch s[j] {
			case '\\':
				j++
			case '"':
				return j + 1
			}
		}
		return -1
	case '{', '[':
		depth := 0
		for j := i; j < len(s); j++ {
			switch s[j] {
			case '"':
				end := jsonValueEnd(s, j)
				if end < 0 {
					return -1
				}
				j = end - 1
			case '{', '[':
				depth++
			case '}', ']':
				if depth--; depth == 0 {
					return j + 1
				}
			}
		}
		return -1
	default:
		j := i
		for j < len(s) && !strings.ContainsRune(" \t\r\n,:]}", rune(s[j])) {
			j++
		}
		if j == i {
			return -1
		}
		return j
	}
}

// jsonText returns the value of raw, a JSON string token, when it is at
// most max bytes: a view of raw when it holds no escapes, else a copy,
// unescaped only when raw is short enough to hold at most max bytes (an
// escape is at most six bytes per byte it stands for). Anything else is "".
func jsonText(raw string, max int) string {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return ""
	}
	inner := raw[1 : len(raw)-1]
	if strings.IndexByte(inner, '\\') < 0 {
		if len(inner) > max {
			return ""
		}
		return inner
	}
	if len(inner) > 6*max {
		return ""
	}
	if s := gjson.Parse(raw).String(); len(s) <= max {
		return s
	}
	return ""
}

// jsonIsObject reports whether raw is an object token.
func jsonIsObject(raw string) bool {
	return len(raw) > 0 && raw[0] == '{'
}

// JSONText returns the string at the object path keys in json (a view,
// BytesView) when it is at most max bytes long, or "". The result may be a
// view of json: copy what is kept (OwnedString). Unlike gjson it never
// copies more than a bounded escaped string, so inspecting a large client
// frame or upstream event allocates nothing of its size.
func JSONText(json string, max int, keys ...string) string {
	return jsonText(jsonGet(json, keys...), max)
}
