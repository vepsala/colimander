package proxy

import "testing"

func TestOnlyNoApprovalFunctions(t *testing.T) {
	cases := []struct {
		names []string
		want  bool
	}{
		{[]string{"graphile_worker.add_job"}, true},
		{[]string{"graphile_worker.add_job", "graphile_worker.add_job"}, true},
		{[]string{"graphile_worker.add_jobs"}, true},
		{[]string{"add_job"}, false},                       // schema must be named
		{[]string{"public.add_job"}, false},                // a look-alike elsewhere
		{[]string{"graphile_worker.complete_jobs"}, false}, // other worker functions still blocked
		{[]string{"graphile_worker.add_job", "get_email"}, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := onlyNoApprovalFunctions(c.names); got != c.want {
			t.Errorf("onlyNoApprovalFunctions(%v) = %v, want %v", c.names, got, c.want)
		}
	}
}
