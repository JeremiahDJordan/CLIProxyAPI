package openai

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Fleet fork: T3 Code's Codex app-server gets the same Responses failure framing
// (response.failed) as other official Codex clients.
func TestCodexResponsesClientRequestAcceptsT3CodeFleet(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Request.Header.Set("User-Agent", "T3 Code/0.164.0 (Mac OS 27.0.1; arm64) xterm-256color (T3 Code; 0.1.2)")
	c.Request.Header.Set("Originator", "T3 Code")
	if !isCodexResponsesClientRequest(c) {
		t.Fatal("T3 Code is not treated as a Codex Responses client")
	}
}
