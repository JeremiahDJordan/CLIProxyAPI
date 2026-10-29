//go:build unix

package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/archive"
)

// Round-4 finding 4: a panic recovered while the writer wrapper or the body
// tee observes the transport loses part of what ingress_end and client_body
// report (bytes_written, the committed status and headers, the body's read
// count), so the request counts a drop: its ingress_end must not look
// complete. Before the fix the writer.write case kept the client's response
// but recorded bytes_written 0 with no capture_drops, and the body.read case
// recorded a body the handler read in full as body_unread. The response is
// unaffected throughout.
func TestArchiveTransportObserverPanicsCountAgainstTheirRequest(t *testing.T) {
	server, spool := newArchiveServer(t, nil)
	for _, stage := range []string{"writer.write", "writer.commit", "body.read"} {
		t.Run(stage, func(t *testing.T) {
			path := "/archive-test/r4/" + stage
			classifyForTest(t, http.MethodPost, path)
			server.engine.POST(path, func(c *gin.Context) {
				echoBody(c)
			})
			archiveTapFault = func(where string) {
				if where == stage {
					panic("injected tap panic in " + where)
				}
			}
			t.Cleanup(func() { archiveTapFault = nil })
			payload := []byte(`answer`)
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload)))
			archiveTapFault = nil
			if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), payload) {
				t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
			}
			events := spoolEvents(t, spool)
			ends := eventsFor(events, archive.TypeIngressEnd, path)
			if len(ends) != 1 {
				t.Fatalf("ingress_end = %v", ends)
			}
			if drops, _ := ends[0]["capture_drops"].(float64); drops < 1 {
				t.Fatalf("ingress_end after a %s panic reports no capture_drops: %v", stage, ends[0])
			}
			if stage == "body.read" {
				bodies := eventsFor(events, archive.TypeClientBody, path)
				if len(bodies) != 1 || bodies[0]["capture"] != archive.CaptureDroppedBody || bodies[0]["drop_reason"] != archive.DropTapPanic {
					t.Fatalf("client_body = %v", bodies)
				}
			}
		})
	}
	if queued := archiveStopQueueBytes(t, spool); queued != 0 {
		t.Fatalf("the panics stranded %v reserved queue bytes", queued)
	}
}
