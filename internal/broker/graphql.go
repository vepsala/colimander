// GraphQL checks for the GitHub broker.
//
// The REST deny rules can't see GraphQL: every call is POST /graphql, and the
// operation is in the body. So the body is parsed here. Queries are allowed,
// because gh reads through GraphQL constantly. Mutations are allowed only when
// every top-level field is on graphQLMutationAllowlist, which covers what gh
// needs for everyday pull request and issue work. Anything else, such as
// deleteRef, deleteBranchProtectionRule or deleteRepository, is denied.
//
// Limit: GraphQL calls aren't scoped to allowed_owners. Most of them identify
// repositories by node ID, which the broker can't map to an owner without an
// extra lookup. The token's own access is still the outer boundary.

package broker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// maxGraphQLBody bounds how much of a request body the broker reads to check it.
const maxGraphQLBody = 1 << 20

// graphQLMutationAllowlist is what gh uses for pull requests, issues, reviews,
// comments, labels and reactions. Nothing here deletes anything or changes
// settings, keys, webhooks or branch protection.
var graphQLMutationAllowlist = map[string]bool{
	"__typename":                    true,
	"createPullRequest":             true,
	"updatePullRequest":             true,
	"updatePullRequestBranch":       true,
	"closePullRequest":              true,
	"reopenPullRequest":             true,
	"markPullRequestReadyForReview": true,
	"convertPullRequestToDraft":     true,
	"mergePullRequest":              true,
	"enablePullRequestAutoMerge":    true,
	"disablePullRequestAutoMerge":   true,
	"requestReviews":                true,
	"addPullRequestReview":          true,
	"submitPullRequestReview":       true,
	"addPullRequestReviewThread":    true,
	"addPullRequestReviewComment":   true,
	"resolveReviewThread":           true,
	"unresolveReviewThread":         true,
	"createIssue":                   true,
	"updateIssue":                   true,
	"closeIssue":                    true,
	"reopenIssue":                   true,
	"addComment":                    true,
	"updateIssueComment":            true,
	"addLabelsToLabelable":          true,
	"removeLabelsFromLabelable":     true,
	"addAssigneesToAssignable":      true,
	"removeAssigneesFromAssignable": true,
	"addReaction":                   true,
	"removeReaction":                true,
}

// readGraphQLBody reads a request body for checking and returns it so it can
// be forwarded unchanged.
func readGraphQLBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxGraphQLBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxGraphQLBody {
		return nil, fmt.Errorf("graphql body over %d bytes", maxGraphQLBody)
	}
	return body, nil
}

// checkGraphQL returns (allowed, reason) for a POST /graphql body.
func (p *Policy) checkGraphQL(body []byte) (bool, string) {
	query, err := graphQLQuery(body)
	if err != nil {
		return false, "graphql: " + err.Error()
	}
	doc, gerr := parser.ParseQuery(&ast.Source{Input: query})
	if gerr != nil {
		return false, "graphql: can't parse the query, so it can't be checked"
	}
	if len(doc.Operations) == 0 {
		return false, "graphql: no operation"
	}
	for _, op := range doc.Operations {
		switch op.Operation {
		case ast.Query:
			continue
		case ast.Mutation:
			if ok, reason := checkMutation(op); !ok {
				return false, reason
			}
		default:
			return false, fmt.Sprintf("graphql: %s operations aren't allowed", op.Operation)
		}
	}
	return true, ""
}

func checkMutation(op *ast.OperationDefinition) (bool, string) {
	var denied []string
	for _, sel := range op.SelectionSet {
		f, ok := sel.(*ast.Field)
		if !ok {
			// A fragment at the top of a mutation could hide any field.
			return false, "graphql: fragments at the top of a mutation aren't allowed"
		}
		if !graphQLMutationAllowlist[f.Name] {
			denied = append(denied, f.Name)
		}
	}
	if len(denied) > 0 {
		sort.Strings(denied)
		return false, fmt.Sprintf("graphql: mutation %s isn't on the broker's allowlist", strings.Join(denied, ", "))
	}
	return true, ""
}

// graphQLQuery extracts "query" from a JSON request body. It refuses batches
// and duplicate keys, so the broker and GitHub can't read different queries
// out of the same body.
func graphQLQuery(body []byte) (string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("body isn't JSON")
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return "", fmt.Errorf("body must be a single JSON object (batches aren't allowed)")
	}
	seen := map[string]bool{}
	query, found := "", false
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return "", fmt.Errorf("body isn't valid JSON")
		}
		key, _ := kt.(string)
		if seen[strings.ToLower(key)] {
			return "", fmt.Errorf("duplicate key %q in body", key)
		}
		seen[strings.ToLower(key)] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", fmt.Errorf("body isn't valid JSON")
		}
		if key == "query" {
			if err := json.Unmarshal(raw, &query); err != nil {
				return "", fmt.Errorf("query must be a string")
			}
			found = true
		}
	}
	if _, err := dec.Token(); err != nil {
		return "", fmt.Errorf("body isn't valid JSON")
	}
	if dec.More() {
		return "", fmt.Errorf("trailing data after the JSON body")
	}
	if !found {
		return "", fmt.Errorf("body has no query")
	}
	return query, nil
}
