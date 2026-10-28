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
	RecorderVersion  = "1b"
)

// Event types (design section 4; docs/FLEET_FORK.md section 3 lists their fields).
const (
	TypeBoot                 = "boot"
	TypeShutdown             = "shutdown"
	TypeHeartbeat            = "heartbeat"
	TypeGap                  = "gap"
	TypeIngressStart         = "ingress_start"
	TypeIngressEnd           = "ingress_end"
	TypeClientBody           = "client_body"
	TypeMetadataOnly         = "metadata_only"
	TypeAttemptStart         = "attempt_start"
	TypeAttemptEnd           = "attempt_end"
	TypeUpstreamRequest      = "upstream_request"
	TypeUpstreamResponseMeta = "upstream_response_meta"
	TypeUpstreamEvent        = "upstream_event"
	TypeUpstreamError        = "upstream_error"
	TypeUpstreamWS           = "upstream_ws"
	TypeDownstreamEvent      = "downstream_event"
	TypeClientWSFrame        = "client_ws_frame"
	TypeUsage                = "usage"
)

// Ingress kinds (design section 5).
const (
	KindHTTP         = "http"
	KindWSConnection = "ws_connection"
	KindWSTurn       = "ws_turn"
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
	// TurnSeq is the WebSocket turn's order on its connection (from 1).
	TurnSeq uint32
	// AttemptSeq numbers the request's provider attempts (from 1); zero
	// when the event belongs to no attempt.
	AttemptSeq uint16
	// SubAttempt numbers the attempt's outbound requests (from 0) on
	// events about one of them; nil otherwise.
	SubAttempt *uint16
	Capture    string
	// BodyDropped names why a body the event would carry was not captured.
	BodyDropped string
	// Body holds the exact bytes; the writer chooses the form and hashes them.
	Body *BodyData
	// Data holds per-type fields. It must marshal to a JSON object whose keys
	// do not repeat the envelope's.
	Data any
	// SizeHint estimates Data's encoded size for the queue reservation.
	SizeHint int64
	// ReportDrops makes the writer record the ingress's drop count as
	// capture_drops when it writes the event (ingress_end), so drops the
	// writer counted for earlier events of the request are included.
	ReportDrops bool

	// ingress is set by Ingress.EmitReserved so writer-side drops count
	// against the request.
	ingress *Ingress
}

// BodyData is a captured body: Bytes, or Chunks in order when the capture
// grew by appending buffers (the client body tee never copies what it read).
type BodyData struct {
	Bytes           []byte
	Chunks          [][]byte
	ContentEncoding string
}

// Len is the body's length in bytes.
func (b *BodyData) Len() int64 {
	if b == nil {
		return 0
	}
	n := int64(len(b.Bytes))
	for _, chunk := range b.Chunks {
		n += int64(len(chunk))
	}
	return n
}

// capacity is what the body's buffers hold in memory.
func (b *BodyData) capacity() int64 {
	if b == nil {
		return 0
	}
	n := int64(cap(b.Bytes))
	for _, chunk := range b.Chunks {
		n += int64(cap(chunk))
	}
	return n
}

// flat returns the body as one buffer. Only the writer joins chunks, off the
// request path.
func (b *BodyData) flat() []byte {
	if len(b.Chunks) == 0 {
		return b.Bytes
	}
	if len(b.Chunks) == 1 && len(b.Bytes) == 0 {
		return b.Chunks[0]
	}
	out := make([]byte, 0, b.Len())
	out = append(out, b.Bytes...)
	for _, chunk := range b.Chunks {
		out = append(out, chunk...)
	}
	return out
}

// reservation charges a body's buffers by their capacity, which is what the
// event keeps in memory until it is written; slack never pays for metadata.
func (e *Event) reservation() int64 {
	return int64(eventOverhead) + e.SizeHint + e.Body.capacity()
}

type envelope struct {
	V            int           `json:"v"`
	BootID       string        `json:"boot_id"`
	Seq          uint64        `json:"seq"`
	TS           string        `json:"ts"`
	Type         string        `json:"type"`
	IngressID    string        `json:"ingress_id,omitempty"`
	ConnectionID string        `json:"connection_id,omitempty"`
	TurnSeq      uint32        `json:"turn_seq,omitempty"`
	AttemptSeq   uint16        `json:"attempt_seq,omitempty"`
	SubAttempt   *uint16       `json:"sub_attempt,omitempty"`
	Body         *bodyEnvelope `json:"body,omitempty"`
	Capture      string        `json:"capture,omitempty"`
	BodyDropped  string        `json:"body_dropped,omitempty"`
	CaptureDrops int64         `json:"capture_drops,omitempty"`
}

type bodyEnvelope struct {
	Form            string  `json:"form"`
	ContentEncoding string  `json:"content_encoding,omitempty"`
	Bytes           int64   `json:"bytes"`
	SHA256          string  `json:"sha256"`
	Value           *string `json:"value,omitempty"`
}

// FormatTime renders RFC 3339 UTC with microseconds, the spool time format.
func FormatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z")
}

// encodeBody picks the body form. Valid UTF-8 is a JSON string (identical
// bytes after decoding), anything else base64, and bodies over the threshold
// are blobs referenced by hash. It returns the blob payload when one is due.
func encodeBody(b *BodyData, threshold int64) (*bodyEnvelope, []byte) {
	data := b.flat()
	sum := sha256.Sum256(data)
	env := &bodyEnvelope{
		ContentEncoding: b.ContentEncoding,
		Bytes:           int64(len(data)),
		SHA256:          hex.EncodeToString(sum[:]),
	}
	switch {
	case threshold > 0 && int64(len(data)) > threshold:
		env.Form = FormBlob
		return env, data
	case utf8.Valid(data):
		env.Form = FormText
		value := string(data)
		env.Value = &value
	default:
		env.Form = FormBase64
		value := base64.StdEncoding.EncodeToString(data)
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
