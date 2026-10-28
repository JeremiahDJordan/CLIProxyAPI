package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"
)

// Versions recorded in every boot event.
const (
	EnvelopeVersion  = 1
	RedactionVersion = 1
	RecorderVersion  = "1a"
)

// Event types (design section 4). Slice 1a emits only a subset.
const (
	TypeBoot         = "boot"
	TypeShutdown     = "shutdown"
	TypeHeartbeat    = "heartbeat"
	TypeGap          = "gap"
	TypeIngressStart = "ingress_start"
	TypeIngressEnd   = "ingress_end"
	TypeClientBody   = "client_body"
	TypeMetadataOnly = "metadata_only"
)

// Capture states (design section 4).
const (
	CaptureFull         = "full"
	CaptureMetadataOnly = "metadata_only"
	CaptureDroppedBody  = "dropped_body"
	CaptureBodyUnread   = "body_unread"
	CaptureDroppedEvent = "dropped_event"
)

// Body forms.
const (
	FormText   = "text"
	FormBase64 = "base64"
	FormBlob   = "blob"
)

// eventOverhead is the queue reservation charged for an event's envelope and
// fields on top of its body and size hint.
const eventOverhead = 1024

// Event is one spool line before the writer assigns boot_id and seq.
type Event struct {
	Type         string
	Time         time.Time
	IngressID    string
	ConnectionID string
	Capture      string
	// Body holds the exact bytes; the writer chooses the form and hashes them.
	Body *BodyData
	// Data holds per-type fields. It must marshal to a JSON object whose keys
	// do not repeat the envelope's.
	Data any
	// SizeHint estimates Data's encoded size for the queue reservation.
	SizeHint int64
}

// BodyData is a captured body.
type BodyData struct {
	Bytes           []byte
	ContentEncoding string
}

func (e *Event) reservation() int64 {
	n := int64(eventOverhead) + e.SizeHint
	if e.Body != nil {
		n += int64(len(e.Body.Bytes))
	}
	return n
}

type envelope struct {
	V            int           `json:"v"`
	BootID       string        `json:"boot_id"`
	Seq          uint64        `json:"seq"`
	TS           string        `json:"ts"`
	Type         string        `json:"type"`
	IngressID    string        `json:"ingress_id,omitempty"`
	ConnectionID string        `json:"connection_id,omitempty"`
	Body         *bodyEnvelope `json:"body,omitempty"`
	Capture      string        `json:"capture,omitempty"`
}

type bodyEnvelope struct {
	Form            string  `json:"form"`
	ContentEncoding string  `json:"content_encoding,omitempty"`
	Bytes           int64   `json:"bytes"`
	SHA256          string  `json:"sha256"`
	Value           *string `json:"value,omitempty"`
}

// formatTime renders RFC 3339 UTC with microseconds.
func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// encodeBody picks the body form. Valid UTF-8 is a JSON string (identical
// bytes after decoding), anything else base64, and bodies over the threshold
// are blobs referenced by hash. It returns the blob payload when one is due.
func encodeBody(b *BodyData, threshold int64) (*bodyEnvelope, []byte) {
	sum := sha256.Sum256(b.Bytes)
	env := &bodyEnvelope{
		ContentEncoding: b.ContentEncoding,
		Bytes:           int64(len(b.Bytes)),
		SHA256:          hex.EncodeToString(sum[:]),
	}
	switch {
	case threshold > 0 && int64(len(b.Bytes)) > threshold:
		env.Form = FormBlob
		return env, b.Bytes
	case utf8.Valid(b.Bytes):
		env.Form = FormText
		value := string(b.Bytes)
		env.Value = &value
	default:
		env.Form = FormBase64
		value := base64.StdEncoding.EncodeToString(b.Bytes)
		env.Value = &value
	}
	return env, nil
}

// marshalCompact encodes v without HTML escaping and without the trailing newline.
func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// encodeLine renders one spool line: the envelope followed by the event's
// per-type fields in the same object, terminated by a newline.
func encodeLine(env *envelope, data any) ([]byte, error) {
	head, err := marshalCompact(env)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return append(head, '\n'), nil
	}
	fields, err := marshalCompact(data)
	if err != nil {
		return nil, err
	}
	if len(fields) < 2 || fields[0] != '{' || fields[len(fields)-1] != '}' {
		return nil, fmt.Errorf("archive: %s fields are not a JSON object", env.Type)
	}
	if len(fields) == 2 {
		return append(head, '\n'), nil
	}
	line := make([]byte, 0, len(head)+len(fields)+1)
	line = append(line, head[:len(head)-1]...)
	line = append(line, ',')
	line = append(line, fields[1:]...)
	return append(line, '\n'), nil
}
