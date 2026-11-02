package proxy

import "testing"

func TestDescribeUpstream(t *testing.T) {
	cases := map[string]string{
		"postgres://user:secret@db.example.com:6543/shop?sslmode=disable": "shop @ db.example.com:6543",
		"host=localhost port=5432 dbname=app user=u password=p":           "app @ localhost:5432",
	}
	for in, want := range cases {
		if got := describeUpstream(in); got != want {
			t.Errorf("describeUpstream(%q) = %q, want %q", in, got, want)
		}
	}
}
