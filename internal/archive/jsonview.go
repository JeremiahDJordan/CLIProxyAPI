package archive

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

// Bounded JSON reads for inspection outside the queue's reservations. gjson
// unescapes every string it returns, and every escaped member name it
// compares on the way, into a copy as large as the string (gjson.Get on an
// 8 MiB escaped ID allocates it twice over). These helpers read raw tokens
// of a view (BytesView) instead and copy nothing: a short escaped string is
// unescaped into a scratch buffer the caller reuses, so the caller can
// check it (against the identities it keeps, and their limits) before it
// copies the few it keeps.

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

// JSONScratch is the buffer a JSON string written with escapes is
// unescaped into (JSONText): allocated when first needed and reused, so
// reading any number of escaped strings through one scratch allocates no
// more than twice the longest value read through it (the buffer only
// grows, at least doubling, up to that read's limit). A string read into it
// is a view of it, valid until the scratch is used again: copy what is
// kept, once it is known to be kept.
type JSONScratch struct{ buf []byte }

// bytes returns n bytes of the buffer, first growing it when it is shorter.
func (s *JSONScratch) bytes(n, limit int) []byte {
	if cap(s.buf) < n {
		s.buf = make([]byte, min(max(n, 2*cap(s.buf)), limit))
	}
	return s.buf[:n]
}

// jsonText returns the value of raw, a JSON string token, when it is at
// most max bytes, or "": a view of raw when it holds no escapes, else its
// value unescaped into scratch, a view of scratch (escaped is then true).
// Only a token short enough to hold at most max bytes is unescaped (an
// escape is at most six bytes per byte it stands for), and unescaping stops
// once the value is longer than max: nothing is allocated but scratch's
// buffer.
func jsonText(raw string, max int, scratch *JSONScratch) (text string, escaped bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", false
	}
	inner := raw[1 : len(raw)-1]
	if strings.IndexByte(inner, '\\') < 0 {
		if len(inner) > max {
			return "", false
		}
		return inner, false
	}
	if len(inner) > 6*max {
		return "", false
	}
	// The value is no longer than inner.
	buf := scratch.bytes(min(len(inner), max), max)
	n, ok := jsonUnescape(buf, inner)
	if !ok || n == 0 {
		return "", false
	}
	return unsafe.String(unsafe.SliceData(buf), n), true
}

// jsonUnescape writes the value of s, the inside of a JSON string token, to
// dst exactly as gjson unescapes it (Parse(token).String(): it ends at a
// control byte or an unknown escape, decodes surrogate pairs, and writes
// U+FFFD for a lone surrogate), and returns its length, or false when it
// is longer than dst.
func jsonUnescape(dst []byte, s string) (int, bool) {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c < ' ':
			return n, true
		case c == '\\':
			i++
			if i >= len(s) {
				return n, true
			}
			switch s[i] {
			case '\\', '/', '"':
				c = s[i]
			case 'b':
				c = '\b'
			case 'f':
				c = '\f'
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			case 'u':
				if i+5 > len(s) {
					return n, true
				}
				r := jsonHexRune(s[i+1:])
				i += 5
				if utf16.IsSurrogate(r) && len(s[i:]) >= 6 && s[i] == '\\' && s[i+1] == 'u' {
					r = utf16.DecodeRune(r, jsonHexRune(s[i+2:]))
					i += 6
				}
				i--
				var enc [utf8.UTFMax]byte
				size := utf8.EncodeRune(enc[:], r)
				if n+size > len(dst) {
					return 0, false
				}
				n += copy(dst[n:], enc[:size])
				continue
			default:
				return n, true
			}
		}
		if n == len(dst) {
			return 0, false
		}
		dst[n] = c
		n++
	}
	return n, true
}

// jsonHexRune is the rune of the four hex digits s starts with, or 0 when
// they are not all hex digits (as gjson reads them).
func jsonHexRune(s string) rune {
	var r rune
	for _, c := range []byte(s[:4]) {
		switch {
		case '0' <= c && c <= '9':
			r = r<<4 | rune(c-'0')
		case 'a' <= c && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case 'A' <= c && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0
		}
	}
	return r
}

// jsonIsObject reports whether raw is an object token.
func jsonIsObject(raw string) bool {
	return len(raw) > 0 && raw[0] == '{'
}

// JSONText returns the string at the object path keys in json (a view,
// BytesView) when it is at most max bytes long, or "". The result is a view
// of json or, when the string is written with escapes, of scratch, valid
// until scratch is used again: copy what is kept (OwnedString). Unlike
// gjson it never copies a string, so inspecting a large client frame or
// upstream event allocates nothing of its size, and reading many strings
// through one scratch allocates nothing per string.
func JSONText(json string, max int, scratch *JSONScratch, keys ...string) string {
	text, _ := jsonText(jsonGet(json, keys...), max, scratch)
	return text
}
