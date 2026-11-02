package policy

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		sql  string
		want Kind
	}{
		// Reads.
		{"SELECT * FROM users", KindRead},
		{"  select 1", KindRead},
		{"\n\t SELECT now()", KindRead},
		{"-- a comment\nSELECT 1", KindRead},
		{"/* block */ SELECT 1", KindRead},
		{"TABLE users", KindRead},
		{"VALUES (1), (2)", KindRead},
		{"SHOW search_path", KindRead},
		{"EXPLAIN SELECT * FROM users", KindRead},
		{"WITH t AS (SELECT 1) SELECT * FROM t", KindRead},
		// A SELECT containing a mutation keyword inside a string literal must
		// still be a read (we only deep-scan WITH/EXPLAIN).
		{"SELECT * FROM audit WHERE action = 'delete'", KindRead},

		// Mutations.
		{"INSERT INTO t VALUES (1)", KindMutation},
		{"update users set name = 'x'", KindMutation},
		{"DELETE FROM t", KindMutation},
		{"TRUNCATE t", KindMutation},
		{"DROP TABLE t", KindMutation},
		{"ALTER TABLE t ADD COLUMN c int", KindMutation},
		{"CREATE TABLE t (id int)", KindMutation},
		{"GRANT SELECT ON t TO bob", KindMutation},
		{"COPY t FROM stdin", KindMutation},
		{"MERGE INTO t USING s ON t.id = s.id", KindMutation},
		// CTE that writes.
		{"WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", KindMutation},
		// EXPLAIN ANALYZE of a write executes the write.
		{"EXPLAIN ANALYZE DELETE FROM t", KindMutation},
		// EXECUTE is opaque, gate it.
		{"EXECUTE my_plan", KindMutation},

		// Session control.
		{"BEGIN", KindSession},
		{"COMMIT", KindSession},
		{"ROLLBACK", KindSession},
		{"SET search_path = public", KindSession},
		{"RESET ALL", KindSession},
		{"DISCARD ALL", KindSession},

		// Empty / comment-only is conservatively a mutation (not a read).
		{"", KindMutation},
		{"-- nothing here", KindMutation},
	}

	for _, c := range cases {
		if got := Classify(c.sql); got != c.want {
			t.Errorf("Classify(%q) = %v, want %v", c.sql, got, c.want)
		}
	}
}

func TestContainsWord(t *testing.T) {
	cases := []struct {
		s, word string
		want    bool
	}{
		{"FOO DELETE BAR", "DELETE", true},
		{"DELETED_AT", "DELETE", false},
		{"X_DELETE", "DELETE", false},
		{"(DELETE", "DELETE", true},
		{"DELETE", "DELETE", true},
		{"NODELETE", "DELETE", false},
	}
	for _, c := range cases {
		if got := containsWord(c.s, c.word); got != c.want {
			t.Errorf("containsWord(%q, %q) = %v, want %v", c.s, c.word, got, c.want)
		}
	}
}
