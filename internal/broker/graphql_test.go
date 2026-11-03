package broker

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func gqlBody(query string) string {
	b, _ := json.Marshal(map[string]any{"query": query, "variables": map[string]any{}})
	return string(b)
}

func testPolicy() *Policy {
	return &Policy{AllowedOwners: []string{"vepsala", "acme"}, DenyRules: DefaultDenyRules()}
}

func TestCheckGraphQLAllowsEverydayGh(t *testing.T) {
	p := testPolicy()
	for _, q := range []string{
		`query { viewer { login } }`,
		`{ repository(owner: "vepsala", name: "x") { pullRequests(first: 5) { nodes { number } } } }`,
		`query PR($id: ID!) { node(id: $id) { id } }`,
		`mutation PullRequestCreate($input: CreatePullRequestInput!) { createPullRequest(input: $input) { pullRequest { url } } }`,
		`mutation { a: addComment(input: {subjectId: "x", body: "hi"}) { clientMutationId } addLabelsToLabelable(input: {labelableId: "x", labelIds: []}) { clientMutationId } }`,
		`# a comment
		mutation { mergePullRequest(input: {pullRequestId: "x"}) { clientMutationId } }`,
	} {
		if ok, reason := p.checkGraphQL([]byte(gqlBody(q))); !ok {
			t.Errorf("denied %q: %s", q, reason)
		}
	}
}

func TestCheckGraphQLDeniesDestructiveMutations(t *testing.T) {
	p := testPolicy()
	cases := map[string]string{
		"branch protection": `mutation { deleteBranchProtectionRule(input: {branchProtectionRuleId: "x"}) { clientMutationId } }`,
		"delete ref":        `mutation { deleteRef(input: {refId: "x"}) { clientMutationId } }`,
		"delete repo":       `mutation { deleteRepository(input: {repositoryId: "x"}) { clientMutationId } }`,
		"delete label":      `mutation { deleteLabel(input: {id: "x"}) { clientMutationId } }`,
		"hidden by alias":   `mutation { createPullRequest: deleteRef(input: {refId: "x"}) { clientMutationId } }`,
		"mixed with allowed": `mutation { addComment(input: {subjectId: "x", body: "hi"}) { clientMutationId }
			deleteRef(input: {refId: "x"}) { clientMutationId } }`,
		"second operation": `query Q { viewer { login } }
			mutation M { deleteRef(input: {refId: "x"}) { clientMutationId } }`,
		"fragment spread": `mutation { ...F } fragment F on Mutation { deleteRef(input: {refId: "x"}) { clientMutationId } }`,
		"inline fragment": `mutation { ... on Mutation { deleteRef(input: {refId: "x"}) { clientMutationId } } }`,
		"subscription":    `subscription { x }`,
		"unparseable":     `mutation { deleteRef(`,
	}
	for name, q := range cases {
		if ok, _ := p.checkGraphQL([]byte(gqlBody(q))); ok {
			t.Errorf("%s: allowed %q", name, q)
		}
	}
}

func TestCheckGraphQLRefusesAmbiguousBodies(t *testing.T) {
	p := testPolicy()
	deleteRef := `mutation { deleteRef(input: {refId: \"x\"}) { clientMutationId } }`
	for name, body := range map[string]string{
		"batch":          `[` + gqlBody(`mutation { deleteRef(input: {refId: "x"}) { clientMutationId } }`) + `]`,
		"duplicate key":  `{"query": "query { viewer { login } }", "query": "` + deleteRef + `"}`,
		"duplicate case": `{"query": "query { viewer { login } }", "Query": "` + deleteRef + `"}`,
		"trailing data":  gqlBody(`query { viewer { login } }`) + `{"query": "` + deleteRef + `"}`,
		"no query":       `{"variables": {}}`,
		"not a string":   `{"query": 1}`,
		"not json":       `query { viewer { login } }`,
	} {
		if ok, _ := p.checkGraphQL([]byte(body)); ok {
			t.Errorf("%s: allowed %s", name, body)
		}
	}
}

func TestCheckGraphQLRequest(t *testing.T) {
	p := testPolicy()
	ok, reason, body := checkGraphQLRequest(p, httptest.NewRequest("POST", "/api/graphql", strings.NewReader(gqlBody(`{ viewer { login } }`))))
	if !ok {
		t.Fatalf("plain query denied: %s", reason)
	}
	if got, _ := io.ReadAll(body); string(got) != gqlBody(`{ viewer { login } }`) {
		t.Errorf("forwarded body changed: %s", got)
	}

	q := gqlBody(`{ viewer { login } }`)
	gz := httptest.NewRequest("POST", "/api/graphql", strings.NewReader(q))
	gz.Header.Set("Content-Encoding", "gzip")
	for name, r := range map[string]*http.Request{
		"GET":          httptest.NewRequest("GET", "/api/graphql?query=x", nil),
		"query string": httptest.NewRequest("POST", "/api/graphql?query=x", strings.NewReader(q)),
		"gzip":         gz,
		"too big":      httptest.NewRequest("POST", "/api/graphql", strings.NewReader(strings.Repeat(" ", maxGraphQLBody)+q)),
	} {
		if ok, _, _ := checkGraphQLRequest(p, r); ok {
			t.Errorf("%s: allowed", name)
		}
	}
}
