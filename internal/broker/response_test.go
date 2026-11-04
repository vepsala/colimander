package broker

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDenyResponseExplainsTheBroker(t *testing.T) {
	b := &broker{}
	cases := []struct {
		path, service, hint string
		json                bool
	}{
		{"/api/repos/o/r", "GitHub", "ask the user to do it on their Mac", true},
		{"/git/o/r.git/git-receive-pack", "GitHub", "Leave remotes as https://github.com/", false},
		{"/fly/v1/apps/x", "Fly.io", "Fly tokens", true},
		{"/doppler/v3/configs", "Doppler", "Ask the user", true},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		b.denyResponse(w, httptest.NewRequest("POST", c.path, nil), "delete-repository: nope")
		if w.Code != 403 {
			t.Errorf("%s: status %d", c.path, w.Code)
		}
		body := w.Body.String()
		if c.json {
			var got struct {
				Message  string   `json:"message"`
				Error    string   `json:"error"`
				Messages []string `json:"messages"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("%s: %v", c.path, err)
			}
			if got.Message == "" || got.Error != got.Message || len(got.Messages) != 1 {
				t.Errorf("%s: every client field should carry the message: %s", c.path, body)
			}
			body = got.Message
		} else if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Errorf("%s: git shows only text/plain bodies, got %q", c.path, ct)
		}
		for _, want := range []string{"Colimander broker, not by " + c.service, "delete-repository: nope", "host.lima.internal", c.hint} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: message lacks %q: %s", c.path, want, body)
			}
		}
	}
}

func TestErrorResponseSaysItIsTheBroker(t *testing.T) {
	w := httptest.NewRecorder()
	(&broker{}).errorResponse(w, httptest.NewRequest("GET", "/api/user", nil), 403, "broker: bad handle")
	var got struct{ Message string }
	json.Unmarshal(w.Body.Bytes(), &got)
	if !strings.Contains(got.Message, "not from GitHub") || !strings.Contains(got.Message, "bad handle") || !strings.Contains(got.Message, "rewire") {
		t.Errorf("message: %s", got.Message)
	}
}
