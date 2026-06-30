package proxy

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/kotisivukamu/pg-agent-proxy/internal/approval"
	"github.com/kotisivukamu/pg-agent-proxy/internal/policy"
)

// handleSimpleQuery processes one simple-protocol Query string end to end.
func (s *session) handleSimpleQuery(ctx context.Context, sql string) {
	if s.isSchemaCommand(sql) {
		s.handleSchemaSimple(ctx)
		s.ready()
		return
	}

	kind := policy.Classify(sql)
	if kind == policy.KindMutation && s.policy.GateMutations() {
		if !s.approveMutation(ctx, kind, sql) {
			s.ready()
			return
		}
	}

	mrr := s.upstream.Exec(ctx, sql)
	for mrr.NextResult() {
		if s.streamResult(ctx, mrr.ResultReader(), true, kind, sql) {
			break
		}
	}
	if err := mrr.Close(); err != nil {
		s.sendQueryError(err)
	}
	s.ready()
}

// approveMutation requests approval for a gated mutation. It returns true when
// the statement may proceed. On denial it queues an ErrorResponse.
func (s *session) approveMutation(ctx context.Context, kind policy.Kind, sql string) bool {
	dec := s.srv.approver.Approve(ctx, approval.Request{
		ID:        approval.NewID(),
		Reason:    approval.ReasonMutation,
		Statement: kind.String(),
		Query:     sql,
		Client:    s.conn.RemoteAddr().String(),
	})
	if !dec.Approved {
		s.log.Warn("mutation denied", "reason", dec.Reason)
		s.sendError("28000", "pg-agent-proxy: statement denied ("+dec.Reason+")")
		return false
	}
	s.log.Info("mutation approved", "reason", dec.Reason)
	return true
}

// streamResult reads a result, anonymizes it, enforces the row limit, and queues
// the response messages. It returns true if it queued an ErrorResponse (so the
// caller should stop processing the batch). It never flushes.
func (s *session) streamResult(ctx context.Context, rr *pgconn.ResultReader, sendRowDesc bool, kind policy.Kind, query string) (failed bool) {
	fds := rr.FieldDescriptions()
	actions := make([]policy.Action, len(fds))
	for i, fd := range fds {
		actions[i] = s.policy.ActionFor(fd.Name)
	}

	// Buffer the whole result so we can anonymize and enforce the row limit
	// before any data leaves the proxy. pgconn reuses the row buffer, so each
	// value must be copied out.
	var rows [][][]byte
	for rr.NextRow() {
		vals := rr.Values()
		row := make([][]byte, len(vals))
		for i, v := range vals {
			switch {
			case v == nil:
				row[i] = nil
			case actions[i] == policy.ActionNone:
				cp := make([]byte, len(v))
				copy(cp, v)
				row[i] = cp
			default:
				row[i] = s.policy.AnonymizeValue(actions[i], fds[i].DataTypeOID, v)
			}
		}
		rows = append(rows, row)
	}

	tag, err := rr.Close()
	if err != nil {
		s.sendQueryError(err)
		return true
	}

	if s.policy.MaxRows() > 0 && len(rows) > s.policy.MaxRows() {
		dec := s.srv.approver.Approve(ctx, approval.Request{
			ID:        approval.NewID(),
			Reason:    approval.ReasonLargeRead,
			Statement: kind.String(),
			Query:     query,
			RowCount:  len(rows),
			Client:    s.conn.RemoteAddr().String(),
		})
		if !dec.Approved {
			s.log.Warn("large read denied", "rows", len(rows), "reason", dec.Reason)
			s.sendError("53400", fmt.Sprintf(
				"pg-agent-proxy: result of %d rows exceeds limit of %d and was not approved (%s)",
				len(rows), s.policy.MaxRows(), dec.Reason))
			return true
		}
		s.log.Info("large read approved", "rows", len(rows), "reason", dec.Reason)
	}

	if sendRowDesc && len(fds) > 0 {
		s.be.Send(rowDescription(fds))
	}
	for _, row := range rows {
		s.be.Send(&pgproto3.DataRow{Values: row})
	}
	s.be.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag.String())})
	return false
}

// rowDescription converts pgconn field descriptions to a RowDescription message,
// preserving the upstream formats.
func rowDescription(fds []pgconn.FieldDescription) *pgproto3.RowDescription {
	out := make([]pgproto3.FieldDescription, len(fds))
	for i, fd := range fds {
		out[i] = pgproto3.FieldDescription{
			Name:                 []byte(fd.Name),
			TableOID:             fd.TableOID,
			TableAttributeNumber: fd.TableAttributeNumber,
			DataTypeOID:          fd.DataTypeOID,
			DataTypeSize:         fd.DataTypeSize,
			TypeModifier:         fd.TypeModifier,
			Format:               fd.Format,
		}
	}
	return &pgproto3.RowDescription{Fields: out}
}

// rowDescriptionWithFormats is like rowDescription but overrides each column's
// format code from a portal's result format codes (0, 1, or per-column).
func rowDescriptionWithFormats(fds []pgconn.FieldDescription, formats []int16) *pgproto3.RowDescription {
	rd := rowDescription(fds)
	for i := range rd.Fields {
		rd.Fields[i].Format = formatAt(formats, i)
	}
	return rd
}

// formatAt resolves the format code for column i given protocol format-code
// rules: empty = all text, single = applies to all, otherwise per-column.
func formatAt(formats []int16, i int) int16 {
	switch len(formats) {
	case 0:
		return 0
	case 1:
		return formats[0]
	default:
		if i < len(formats) {
			return formats[i]
		}
		return 0
	}
}
