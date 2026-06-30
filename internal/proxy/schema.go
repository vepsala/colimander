package proxy

import (
	"context"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/kotisivukamu/pg-agent-proxy/internal/policy"
)

// textOID is the PostgreSQL OID for the text type.
const textOID = 25

// introspectSQL lists every user column with its type.
const introspectSQL = `
SELECT table_schema, table_name, column_name, data_type, ordinal_position
FROM information_schema.columns
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY table_schema, table_name, ordinal_position`

var schemaColumns = []string{"table_schema", "table_name", "column_name", "data_type", "pii_action"}

// isSchemaCommand reports whether sql is the special schema-introspection call.
func (s *session) isSchemaCommand(sql string) bool {
	return strings.Contains(strings.ToLower(sql), strings.ToLower(s.srv.cfg.SchemaFunction)+"(")
}

// schemaRowDescription is the RowDescription for the synthetic schema result.
func schemaRowDescription() *pgproto3.RowDescription {
	fds := make([]pgproto3.FieldDescription, len(schemaColumns))
	for i, name := range schemaColumns {
		fds[i] = pgproto3.FieldDescription{
			Name:         []byte(name),
			DataTypeOID:  textOID,
			DataTypeSize: -1,
			TypeModifier: -1,
		}
	}
	return &pgproto3.RowDescription{Fields: fds}
}

// schemaRows introspects the upstream and returns the synthetic rows, each
// annotated with the PII action this connection's policy would apply.
func (s *session) schemaRows(ctx context.Context) ([][][]byte, error) {
	results, err := s.upstream.Exec(ctx, introspectSQL).ReadAll()
	if err != nil {
		return nil, err
	}
	result := results[len(results)-1]

	idx := map[string]int{}
	for i, fd := range result.FieldDescriptions {
		idx[fd.Name] = i
	}
	cell := func(row [][]byte, name string) []byte {
		if i, ok := idx[name]; ok && i < len(row) {
			return row[i]
		}
		return nil
	}

	rows := make([][][]byte, 0, len(result.Rows))
	for _, row := range result.Rows {
		column := cell(row, "column_name")
		rows = append(rows, [][]byte{
			cell(row, "table_schema"),
			cell(row, "table_name"),
			column,
			cell(row, "data_type"),
			[]byte(actionName(s.policy.ActionFor(string(column)))),
		})
	}
	return rows, nil
}

// handleSchemaSimple answers the schema call over the simple query protocol.
func (s *session) handleSchemaSimple(ctx context.Context) {
	rows, err := s.schemaRows(ctx)
	if err != nil {
		s.sendQueryError(err)
		return
	}
	s.be.Send(schemaRowDescription())
	for _, row := range rows {
		s.be.Send(&pgproto3.DataRow{Values: row})
	}
	s.be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT " + strconv.Itoa(len(rows)))})
}

// executeSchema answers the schema call over the extended protocol (the
// RowDescription, if requested, was already sent during Describe).
func (s *session) executeSchema(ctx context.Context) {
	rows, err := s.schemaRows(ctx)
	if err != nil {
		s.sendQueryError(err)
		s.batchFailed = true
		return
	}
	for _, row := range rows {
		s.be.Send(&pgproto3.DataRow{Values: row})
	}
	s.be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT " + strconv.Itoa(len(rows)))})
}

func actionName(a policy.Action) string {
	switch a {
	case policy.ActionHash:
		return "hash"
	case policy.ActionRedact:
		return "redact"
	case policy.ActionLabel:
		return "label"
	default:
		return ""
	}
}
