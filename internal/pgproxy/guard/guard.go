// Package guard decides, before a statement reaches the upstream database,
// whether it may run. It parses SQL with PostgreSQL's own parser and applies:
//
//   - a global ban on server, file and credential access, for every statement;
//   - strict rules for statements touching a relation that holds PII, so its
//     values can only leave as plain columns the proxy can mask.
//
// This guards against accidental exposure by a well-meaning agent. It is not a
// security boundary against someone deliberately digging for data: a renamed
// view column, for example, gets past it. Trip results exist for that case, so
// behaviour no honest agent needs stops the connection altogether.
package guard

import (
	"fmt"
	"sort"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
	pgquery "github.com/wasilibs/go-pgquery"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/vepsala/colimander/internal/pgproxy/policy"
)

// Severity is the outcome of checking a statement.
type Severity int

const (
	// Allow lets the statement run.
	Allow Severity = iota
	// Block rejects the statement with a message the agent can act on.
	Block
	// Trip rejects the statement and suspends the connection: an honest agent
	// has no reason to attempt it.
	Trip
)

// Decision is the result of checking a statement.
type Decision struct {
	Severity Severity
	// Message explains a Block or Trip to the agent.
	Message string
	// Kind classifies the whole statement, including every statement in a
	// multi-statement string.
	Kind policy.Kind
	// Strict reports that the statement touches a relation with PII.
	Strict bool
	// UserFunction reports a call to a non-built-in function outside strict
	// mode. It may write or read anything, so it needs approval like a mutation.
	UserFunction bool
	// Unknown lists relations missing from the catalog. The catalog may be
	// stale: callers should refresh it and check again.
	Unknown []string
}

// Relation is a table-like object in the upstream database.
type Relation struct {
	Name string
	// Kind is pg_class.relkind: r and p are tables; v, m and f are views,
	// materialized views and foreign tables.
	Kind    byte
	Columns []string
}

// Catalog describes the upstream schema. The zero value means the schema could
// not be read, and every statement is treated as strict.
type Catalog struct {
	Known     bool
	Relations map[string][]Relation // keyed by lower-case name, across schemas
	UserFuncs map[string]bool       // lower-case names of non-built-in functions
}

// Rules are the per-connection settings Check applies.
type Rules struct {
	Policy *policy.Policy
	// StrictAll treats every relation as strict unless listed in SafeRelations.
	StrictAll bool
	// SafeRelations are relations reviewed as holding no PII.
	SafeRelations []string
}

// tripFunctionPrefixes are functions that reach the server's files or other
// servers, or reveal data no application query needs.
var tripFunctionPrefixes = []string{
	"pg_read_file", "pg_read_binary_file", "pg_ls_", "pg_stat_file", "pg_file_",
	"lo_", "loread", "lowrite", "dblink", "query_to_xml", "table_to_xml",
	"schema_to_xml", "database_to_xml", "cursor_to_xml", "pg_reload_conf",
	"pg_rotate_logfile", "pg_logfile_rotate", "pg_current_logfile",
}

// blockedFunctions are refused, but an agent can reach for them while debugging,
// so they don't suspend anything.
var blockedFunctions = map[string]string{
	"pg_terminate_backend": "server administration is not allowed through this proxy",
	"pg_cancel_backend":    "server administration is not allowed through this proxy",
	"set_config":           "changing settings this way is not allowed through this proxy; use SET",
}

// blockedRelations store real column values or other sessions' query text.
// Agents reach for these when investigating performance, so they don't trip.
var blockedRelations = map[string]bool{
	"pg_stats": true, "pg_stats_ext": true, "pg_stats_ext_exprs": true,
	"pg_statistic": true, "pg_statistic_ext_data": true, "pg_stat_activity": true,
}

// tripRelations hold credentials or raw large objects.
var tripRelations = map[string]bool{
	"pg_authid": true, "pg_shadow": true, "pg_user_mapping": true,
	"pg_user_mappings": true, "pg_largeobject": true, "pg_hba_file_rules": true,
	"pg_file_settings": true,
}

// blockedSettings would undo read-only mode or change who the session runs as.
var blockedSettings = map[string]bool{
	"role": true, "session_authorization": true,
	"default_transaction_read_only": true, "transaction_read_only": true,
}

// strictFunctions may produce computed results in a strict statement, as long as
// their arguments don't reference a PII column. Everything else is refused, so a
// function nobody thought of fails safe rather than leaking.
var strictFunctions = map[string]bool{
	"count": true, "sum": true, "avg": true, "min": true, "max": true,
	"stddev": true, "stddev_pop": true, "stddev_samp": true,
	"variance": true, "var_pop": true, "var_samp": true,
	"bool_and": true, "bool_or": true, "every": true,
	"row_number": true, "rank": true, "dense_rank": true,
	"now": true, "date_trunc": true, "date_part": true, "extract": true, "age": true,
	"round": true, "floor": true, "ceil": true, "ceiling": true, "abs": true, "mod": true,
	"greatest": true, "least": true, "nullif": true,
	"lower": true, "upper": true, "length": true, "char_length": true, "trim": true, "btrim": true,
}

const (
	msgExplicitColumns = "this table holds PII, so select explicit columns; whole rows and conversions to JSON or text can't be masked"
	msgComputedPrefix  = "computed results on tables with PII are limited to common aggregates and date, number and basic text functions"
)

// Check parses sql and decides whether it may run.
func Check(sql string, rules Rules, cat Catalog) Decision {
	tree, err := pgquery.Parse(sql)
	if err != nil {
		return Decision{
			Severity: Block,
			Kind:     policy.KindMutation,
			Message:  "pg-agent-proxy could not parse this statement, so it was not run: " + err.Error(),
		}
	}

	c := &checker{rules: rules, cat: cat, safe: map[string]bool{}, ctes: map[string]bool{}, aliases: map[string]string{}}
	for _, name := range rules.SafeRelations {
		c.safe[strings.ToLower(lastPart(name))] = true
	}

	d := Decision{Kind: classify(sql, tree)}
	for _, raw := range tree.Stmts {
		c.collect(raw)
	}
	c.resolveRelations()
	d.Strict = c.strict
	d.Unknown = c.unknown

	for _, raw := range tree.Stmts {
		c.global(raw)
	}
	if c.strict {
		for _, raw := range tree.Stmts {
			c.strictChecks(raw)
		}
	}
	if !c.strict && len(c.userFuncs) > 0 {
		d.UserFunction = true
		d.Kind = policy.KindMutation
	}

	switch {
	case c.tripMsg != "":
		d.Severity, d.Message = Trip, c.tripMsg
	case c.blockMsg != "":
		d.Severity, d.Message = Block, c.blockMsg
	}
	return d
}

// classify takes the most cautious kind across all statements, so a write can't
// hide behind a leading SELECT.
func classify(sql string, tree *pg.ParseResult) policy.Kind {
	if len(tree.Stmts) == 0 {
		return policy.KindSession
	}
	best := policy.KindSession
	for _, raw := range tree.Stmts {
		kind := policy.Classify(statementText(sql, raw))
		walk(raw, func(m proto.Message) {
			switch m.(type) {
			case *pg.InsertStmt, *pg.UpdateStmt, *pg.DeleteStmt, *pg.MergeStmt:
				kind = policy.KindMutation
			case *pg.SelectStmt:
				if m.(*pg.SelectStmt).IntoClause != nil {
					kind = policy.KindMutation
				}
			}
		})
		switch {
		case kind == policy.KindMutation:
			return policy.KindMutation
		case kind == policy.KindRead:
			best = policy.KindRead
		}
	}
	return best
}

// statementText slices one statement out of a multi-statement string.
func statementText(sql string, raw *pg.RawStmt) string {
	start := int(raw.StmtLocation)
	if start < 0 || start > len(sql) {
		return sql
	}
	end := len(sql)
	if raw.StmtLen > 0 && start+int(raw.StmtLen) <= len(sql) {
		end = start + int(raw.StmtLen)
	}
	return sql[start:end]
}

type checker struct {
	rules Rules
	cat   Catalog
	safe  map[string]bool

	relations []string          // lower-case relation names referenced
	ctes      map[string]bool   // lower-case CTE names, which aren't real relations
	aliases   map[string]string // lower-case alias or name, to relation name or ""

	strict    bool
	protected map[string]bool
	unknown   []string
	userFuncs []string

	tripMsg  string
	blockMsg string
}

func (c *checker) trip(format string, args ...any) {
	if c.tripMsg == "" {
		c.tripMsg = fmt.Sprintf(format, args...)
	}
}

func (c *checker) block(format string, args ...any) {
	if c.blockMsg == "" {
		c.blockMsg = fmt.Sprintf(format, args...)
	}
}

// collect records the relations, aliases and CTEs a statement refers to.
func (c *checker) collect(root proto.Message) {
	walk(root, func(m proto.Message) {
		switch n := m.(type) {
		case *pg.RangeVar:
			name := strings.ToLower(n.Relname)
			c.relations = append(c.relations, name)
			c.aliases[name] = name
			if n.Alias != nil && n.Alias.Aliasname != "" {
				c.aliases[strings.ToLower(n.Alias.Aliasname)] = name
			}
		case *pg.RangeSubselect:
			if n.Alias != nil && n.Alias.Aliasname != "" {
				c.aliases[strings.ToLower(n.Alias.Aliasname)] = ""
			}
		case *pg.RangeFunction:
			if n.Alias != nil && n.Alias.Aliasname != "" {
				c.aliases[strings.ToLower(n.Alias.Aliasname)] = ""
			}
		case *pg.CommonTableExpr:
			name := strings.ToLower(n.Ctename)
			c.ctes[name] = true
			c.aliases[name] = ""
		}
	})
}

// resolveRelations decides whether the statement is strict, and which column
// names are protected. A statement is strict as a whole if any relation is.
func (c *checker) resolveRelations() {
	c.protected = map[string]bool{}
	for _, rule := range c.rules.Policy.Rules() {
		if policy.ParseAction(rule.Action) != policy.ActionNone {
			c.protected[strings.ToLower(rule.Name)] = true
		}
	}
	if !c.cat.Known {
		c.strict = true // can't tell what holds PII, so assume everything does
		return
	}

	seenUnknown := map[string]bool{}
	for _, name := range c.relations {
		if c.ctes[name] {
			continue
		}
		rels, ok := c.cat.Relations[name]
		if !ok {
			if !strings.HasPrefix(name, "pg_") && name != "columns" && name != "tables" && !seenUnknown[name] {
				seenUnknown[name] = true
				c.unknown = append(c.unknown, name)
			}
			continue
		}
		// Same name in several schemas: any strict one makes the statement strict.
		for _, rel := range rels {
			if c.relationIsStrict(rel) {
				c.strict = true
			}
			for _, col := range rel.Columns {
				if c.rules.Policy.ActionForOrigin(rel.Name, col) != policy.ActionNone {
					c.protected[strings.ToLower(col)] = true
				}
			}
		}
	}
	sort.Strings(c.unknown)
}

func (c *checker) relationIsStrict(rel Relation) bool {
	name := strings.ToLower(rel.Name)
	if c.safe[name] {
		return false
	}
	if c.rules.StrictAll {
		return true
	}
	switch rel.Kind {
	case 'v', 'm', 'f':
		return true // may read a PII table, and we can't see which columns
	}
	for _, col := range rel.Columns {
		if c.rules.Policy.ActionForOrigin(rel.Name, col) != policy.ActionNone {
			return true
		}
	}
	return false
}

// global applies the rules that hold for every statement.
func (c *checker) global(root proto.Message) {
	walk(root, func(m proto.Message) {
		switch n := m.(type) {
		case *pg.CopyStmt:
			if n.IsProgram || n.Filename != "" {
				c.trip("COPY to or from a server file or program is not allowed through this proxy")
			} else {
				c.block("COPY is not allowed through this proxy; use SELECT or INSERT")
			}
		case *pg.DoStmt:
			c.block("DO blocks are not allowed through this proxy")
		case *pg.CreateFunctionStmt:
			c.block("creating functions is not allowed through this proxy")
		case *pg.LoadStmt, *pg.AlterSystemStmt, *pg.CreateRoleStmt, *pg.AlterRoleStmt,
			*pg.AlterRoleSetStmt, *pg.DropRoleStmt, *pg.GrantRoleStmt, *pg.CreateExtensionStmt,
			*pg.CreateForeignServerStmt, *pg.CreateUserMappingStmt:
			c.trip("changing roles, extensions or server configuration is not allowed through this proxy")
		case *pg.DiscardStmt:
			if n.Target == pg.DiscardMode_DISCARD_ALL {
				c.block("DISCARD ALL is not allowed through this proxy because it would reset read-only mode")
			}
		case *pg.VariableSetStmt:
			if n.Kind == pg.VariableSetKind_VAR_RESET_ALL {
				c.block("RESET ALL is not allowed through this proxy because it would reset read-only mode")
			}
			if blockedSettings[strings.ToLower(n.Name)] {
				c.block("changing %s is not allowed through this proxy", strings.ToLower(n.Name))
			}
		case *pg.DefElem:
			if n.Defname == "transaction_read_only" && n.Arg.GetAConst().GetIval().GetIval() == 0 {
				c.block("read-write transactions are controlled by the proxy; run the write and it will ask for approval")
			}
		case *pg.RangeVar:
			name := strings.ToLower(n.Relname)
			if c.ctes[name] {
				return
			}
			if tripRelations[name] {
				c.trip("reading %s is not allowed through this proxy", name)
			} else if blockedRelations[name] {
				c.block("reading %s is not allowed through this proxy because it can expose real column values", name)
			}
		case *pg.FuncCall:
			name := funcName(n)
			for _, prefix := range tripFunctionPrefixes {
				if strings.HasPrefix(name, prefix) {
					c.trip("%s is not allowed through this proxy", name)
				}
			}
			if msg, ok := blockedFunctions[name]; ok {
				c.block("%s: %s", name, msg)
			}
			if c.cat.UserFuncs[name] {
				c.userFuncs = append(c.userFuncs, name)
			}
		}
	})
}

// strictChecks applies the rules for statements that touch PII.
func (c *checker) strictChecks(root proto.Message) {
	if len(c.userFuncs) > 0 {
		c.block("custom function %s can't be used alongside tables that hold PII", c.userFuncs[0])
	}
	walk(root, func(m proto.Message) {
		switch n := m.(type) {
		case *pg.ColumnRef:
			if c.isWholeRow(n) {
				c.block(msgExplicitColumns)
			}
		case *pg.SelectStmt:
			setOp := n.Op != pg.SetOperation_SETOP_NONE
			c.checkTargets(n.TargetList, setOp || c.partOfSetOp(root, n))
		case *pg.InsertStmt:
			c.checkTargets(n.ReturningList, false)
		case *pg.UpdateStmt:
			c.checkTargets(n.ReturningList, false)
		case *pg.DeleteStmt:
			c.checkTargets(n.ReturningList, false)
		case *pg.MergeStmt:
			c.checkTargets(n.ReturningList, false)
		}
	})
}

// partOfSetOp reports whether sel is an arm of a UNION, INTERSECT or EXCEPT.
// PostgreSQL doesn't report a source column for those results, so the proxy
// couldn't mask a renamed PII column coming out of one.
func (c *checker) partOfSetOp(root proto.Message, sel *pg.SelectStmt) bool {
	found := false
	walk(root, func(m proto.Message) {
		if parent, ok := m.(*pg.SelectStmt); ok && parent.Op != pg.SetOperation_SETOP_NONE {
			if parent.Larg == sel || parent.Rarg == sel {
				found = true
			}
		}
	})
	return found
}

func (c *checker) checkTargets(targets []*pg.Node, setOp bool) {
	for _, node := range targets {
		res := node.GetResTarget()
		if res == nil || res.Val == nil {
			continue
		}
		c.checkTarget(res.Val, setOp)
	}
}

func (c *checker) checkTarget(val *pg.Node, setOp bool) {
	if ref := val.GetColumnRef(); ref != nil {
		if setOp && c.isProtectedRef(ref) {
			c.block("PII column %s can't be used in UNION, INTERSECT or EXCEPT because its masking would be lost", refName(ref))
		}
		if setOp && hasStar(ref) {
			c.block("list columns explicitly when using UNION, INTERSECT or EXCEPT on tables with PII")
		}
		return // plain columns are masked by their origin
	}
	if val.GetAConst() != nil || val.GetParamRef() != nil || val.GetSqlvalueFunction() != nil {
		return
	}
	// count(email) reveals nothing about the values themselves.
	if fn := val.GetFuncCall(); fn != nil && funcName(fn) == "count" && len(fn.AggOrder) == 0 && fn.AggFilter == nil {
		return
	}

	walk(val, func(m proto.Message) {
		switch n := m.(type) {
		case *pg.SubLink, *pg.SelectStmt:
			c.block("subqueries in the select list can't be masked on tables with PII; join instead")
		case *pg.RowExpr:
			c.block(msgExplicitColumns)
		case *pg.ColumnRef:
			if hasStar(n) {
				c.block(msgExplicitColumns)
			}
			if c.isProtectedRef(n) {
				c.block("%s is PII and can only be selected directly, where it's masked", refName(n))
			}
		case *pg.FuncCall:
			if name := funcName(n); !strictFunctions[name] {
				c.block("%s: %s; select explicit columns or mark this table as safe", name, msgComputedPrefix)
			}
		}
	})
}

// isWholeRow reports a reference to a row rather than a column, as in
// "select u from users u".
func (c *checker) isWholeRow(ref *pg.ColumnRef) bool {
	if len(ref.Fields) != 1 {
		return false
	}
	name := strings.ToLower(ref.Fields[0].GetString_().GetSval())
	if name == "" {
		return false
	}
	relName, isAlias := c.aliases[name]
	if !isAlias {
		return false
	}
	// A column can share its name with a relation; only a real column clears it.
	if relName != "" {
		for _, rel := range c.cat.Relations[relName] {
			for _, col := range rel.Columns {
				if strings.EqualFold(col, name) {
					return false
				}
			}
		}
	}
	return true
}

func (c *checker) isProtectedRef(ref *pg.ColumnRef) bool {
	if len(ref.Fields) == 0 {
		return false
	}
	name := ref.Fields[len(ref.Fields)-1].GetString_().GetSval()
	return c.protected[strings.ToLower(name)]
}

func hasStar(ref *pg.ColumnRef) bool {
	for _, f := range ref.Fields {
		if f.GetAStar() != nil {
			return true
		}
	}
	return false
}

func refName(ref *pg.ColumnRef) string {
	if len(ref.Fields) == 0 {
		return "column"
	}
	return ref.Fields[len(ref.Fields)-1].GetString_().GetSval()
}

func funcName(fn *pg.FuncCall) string {
	if len(fn.Funcname) == 0 {
		return ""
	}
	return strings.ToLower(fn.Funcname[len(fn.Funcname)-1].GetString_().GetSval())
}

func lastPart(qualified string) string {
	if i := strings.LastIndexByte(qualified, '.'); i >= 0 {
		return qualified[i+1:]
	}
	return qualified
}

// walk visits m and every message beneath it. It goes through protobuf
// reflection rather than a list of node types, so syntax added to a future
// parser can't be skipped by accident.
func walk(m proto.Message, visit func(proto.Message)) {
	if m == nil {
		return
	}
	var rec func(protoreflect.Message)
	rec = func(r protoreflect.Message) {
		if !r.IsValid() {
			return
		}
		visit(r.Interface())
		r.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			switch {
			case fd.IsList() && fd.Kind() == protoreflect.MessageKind:
				list := v.List()
				for i := 0; i < list.Len(); i++ {
					rec(list.Get(i).Message())
				}
			case fd.Kind() == protoreflect.MessageKind && !fd.IsMap():
				rec(v.Message())
			}
			return true
		})
	}
	rec(m.ProtoReflect())
}
