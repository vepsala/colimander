package proxy

import (
	"context"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/kotisivukamu/pg-agent-proxy/internal/policy"
)

// handleParse records a client-prepared statement. The query is not sent
// upstream yet; execution happens at Execute via ExecParams.
func (s *session) handleParse(m *pgproto3.Parse) {
	if s.batchFailed {
		return
	}
	s.statements[m.Name] = &preparedStmt{
		query:     m.Query,
		kind:      policy.Classify(m.Query),
		paramOIDs: m.ParameterOIDs,
		isSchema:  s.isSchemaCommand(m.Query),
	}
	s.be.Send(&pgproto3.ParseComplete{})
}

// handleBind binds parameters to a portal.
func (s *session) handleBind(m *pgproto3.Bind) {
	if s.batchFailed {
		return
	}
	s.portals[m.DestinationPortal] = &portal{
		stmt:          m.PreparedStatement,
		paramFormats:  m.ParameterFormatCodes,
		params:        m.Parameters,
		resultFormats: m.ResultFormatCodes,
	}
	s.be.Send(&pgproto3.BindComplete{})
}

// handleDescribe answers a Describe for a statement or portal.
func (s *session) handleDescribe(ctx context.Context, m *pgproto3.Describe) {
	if s.batchFailed {
		return
	}
	switch m.ObjectType {
	case 'S':
		st := s.statements[m.Name]
		if st == nil {
			s.failBatch("26000", "unknown prepared statement "+m.Name)
			return
		}
		if st.isSchema {
			s.be.Send(&pgproto3.ParameterDescription{})
			s.be.Send(schemaRowDescription())
			return
		}
		if err := s.ensureFields(ctx, st); err != nil {
			s.sendQueryError(err)
			s.batchFailed = true
			return
		}
		s.be.Send(&pgproto3.ParameterDescription{ParameterOIDs: st.paramOIDs})
		if len(st.fields) == 0 {
			s.be.Send(&pgproto3.NoData{})
		} else {
			s.be.Send(rowDescription(st.fields))
		}
	case 'P':
		por := s.portals[m.Name]
		if por == nil {
			s.failBatch("34000", "unknown portal "+m.Name)
			return
		}
		st := s.statements[por.stmt]
		if st == nil {
			s.failBatch("26000", "unknown prepared statement "+por.stmt)
			return
		}
		if st.isSchema {
			s.be.Send(schemaRowDescription())
			return
		}
		if err := s.ensureFields(ctx, st); err != nil {
			s.sendQueryError(err)
			s.batchFailed = true
			return
		}
		if len(st.fields) == 0 {
			s.be.Send(&pgproto3.NoData{})
		} else {
			s.be.Send(rowDescriptionWithFormats(st.fields, por.resultFormats))
		}
	}
}

// handleExecute runs a bound portal.
func (s *session) handleExecute(ctx context.Context, m *pgproto3.Execute) {
	if s.batchFailed {
		return
	}
	por := s.portals[m.Portal]
	if por == nil {
		s.failBatch("34000", "unknown portal "+m.Portal)
		return
	}
	st := s.statements[por.stmt]
	if st == nil {
		s.failBatch("26000", "unknown prepared statement "+por.stmt)
		return
	}

	if st.isSchema {
		s.executeSchema(ctx)
		return
	}

	if st.kind == policy.KindMutation && s.policy.GateMutations() {
		if !s.approveMutation(ctx, st.kind, st.query) {
			s.batchFailed = true
			return
		}
	}

	rr := s.upstream.ExecParams(ctx, st.query, por.params, st.paramOIDs, por.paramFormats, por.resultFormats)
	if s.streamResult(ctx, rr, false, st.kind, st.query) {
		s.batchFailed = true
	}
}

// handleClose forgets a statement or portal.
func (s *session) handleClose(m *pgproto3.Close) {
	if s.batchFailed {
		return
	}
	switch m.ObjectType {
	case 'S':
		delete(s.statements, m.Name)
	case 'P':
		delete(s.portals, m.Name)
	}
	s.be.Send(&pgproto3.CloseComplete{})
}

// ensureFields populates a statement's result field descriptions by preparing it
// upstream once. Cached thereafter.
func (s *session) ensureFields(ctx context.Context, st *preparedStmt) error {
	if st.described {
		return nil
	}
	sd, err := s.upstream.Prepare(ctx, "", st.query, st.paramOIDs)
	if err != nil {
		return err
	}
	st.fields = sd.Fields
	if len(st.paramOIDs) == 0 {
		st.paramOIDs = sd.ParamOIDs
	}
	st.described = true
	return nil
}

// failBatch queues an ErrorResponse and enters the skip-until-Sync state.
func (s *session) failBatch(code, message string) {
	s.sendError(code, message)
	s.batchFailed = true
}
