// Package store provides the storage interface and an in-memory implementation
// for the DSSP gateway. Production deployments should implement the Store
// interface with a persistent backend (PostgreSQL, DynamoDB, etc.).
package store

import (
	"fmt"
	"sync"

	"github.com/dssp-protocol/gateway/internal/types"
)

// ListOptions controls pagination and filtering for list operations.
type ListOptions struct {
	Limit  int
	Offset int
	Status string // filter by status (contracts)
	OwnerOrgID string // filter by owner org
}

type EventListOptions struct {
	Limit      int
	Offset     int
	EventType  string
	SessionID  string
	ContractID string
	Since      string // ISO 8601 timestamp
}

type ContractUpdate struct {
	Status           string
	RevocationReason string
	Version          *int
}

type SessionUpdate struct {
	Status        string
	CompletedAt   string
	LastHeartbeat string
	ResultID      string
}

type Store interface {
	CreateManifest(m *types.Manifest) error
	GetManifest(id string) (*types.Manifest, error)
	ListManifests(opts ListOptions) ([]*types.Manifest, int, error)

	CreateContract(c *types.Contract) error
	GetContract(id string) (*types.Contract, error)
	UpdateContract(id string, update ContractUpdate) error
	ListContracts(opts ListOptions) ([]*types.Contract, int, error)

	CreateSession(s *types.Session) error
	GetSession(id string) (*types.Session, error)
	UpdateSession(id string, update SessionUpdate) error
	CountActiveSessions(contractID string) (int, error)
	ListSessions(opts ListOptions) ([]*types.Session, int, error)

	StoreResult(r *types.Result) error
	GetResult(sessionID string) (*types.Result, error)
	GetResultByID(resultID string) (*types.Result, error)

	AppendEvent(e *types.AuditEvent) error
	GetEvents(opts EventListOptions) ([]*types.AuditEvent, int, error)
}

// MemoryStore is a thread-safe, in-memory Store implementation for
// development, testing, and the reference gateway.
type MemoryStore struct {
	mu sync.RWMutex

	manifests    map[string]*types.Manifest    // keyed by manifest_id
	contracts    map[string]*types.Contract     // keyed by contract_id
	sessions     map[string]*types.Session      // keyed by session_id
	results      map[string]*types.Result       // keyed by session_id
	resultsByID  map[string]*types.Result       // keyed by result_id
	auditEvents  []*types.AuditEvent            // append-only ordered list

	// Insertion order for deterministic listing.
	manifestOrder []string
	contractOrder []string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		manifests:   make(map[string]*types.Manifest),
		contracts:   make(map[string]*types.Contract),
		sessions:    make(map[string]*types.Session),
		results:     make(map[string]*types.Result),
		resultsByID: make(map[string]*types.Result),
		auditEvents: make([]*types.AuditEvent, 0, 256),
	}
}

func (s *MemoryStore) CreateManifest(m *types.Manifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.manifests[m.ManifestID]; exists {
		return fmt.Errorf("manifest %s already exists", m.ManifestID)
	}
	s.manifests[m.ManifestID] = m
	s.manifestOrder = append(s.manifestOrder, m.ManifestID)
	return nil
}

func (s *MemoryStore) GetManifest(id string) (*types.Manifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, ok := s.manifests[id]
	if !ok {
		return nil, fmt.Errorf("manifest %s not found", id)
	}
	return m, nil
}

func (s *MemoryStore) ListManifests(opts ListOptions) ([]*types.Manifest, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var all []*types.Manifest
	for _, id := range s.manifestOrder {
		m := s.manifests[id]
		if opts.OwnerOrgID != "" && m.Owner.OrgID != opts.OwnerOrgID {
			continue
		}
		all = append(all, m)
	}

	total := len(all)
	start, end := paginate(total, opts.Offset, opts.Limit)
	return all[start:end], total, nil
}

func (s *MemoryStore) CreateContract(c *types.Contract) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.contracts[c.ContractID]; exists {
		return fmt.Errorf("contract %s already exists", c.ContractID)
	}
	s.contracts[c.ContractID] = c
	s.contractOrder = append(s.contractOrder, c.ContractID)
	return nil
}

func (s *MemoryStore) GetContract(id string) (*types.Contract, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	c, ok := s.contracts[id]
	if !ok {
		return nil, fmt.Errorf("contract %s not found", id)
	}
	return c, nil
}

func (s *MemoryStore) UpdateContract(id string, update ContractUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.contracts[id]
	if !ok {
		return fmt.Errorf("contract %s not found", id)
	}

	if update.Status != "" {
		c.Status = update.Status
	}
	if update.RevocationReason != "" {
		c.RevocationReason = update.RevocationReason
		c.RevokedAt = types.NowUTC()
	}
	if update.Version != nil {
		c.Version = *update.Version
	}
	c.UpdatedAt = types.NowUTC()
	return nil
}

func (s *MemoryStore) ListContracts(opts ListOptions) ([]*types.Contract, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var all []*types.Contract
	for _, id := range s.contractOrder {
		c := s.contracts[id]
		if opts.Status != "" && c.Status != opts.Status {
			continue
		}
		if opts.OwnerOrgID != "" && c.Owner.OrgID != opts.OwnerOrgID {
			continue
		}
		all = append(all, c)
	}

	total := len(all)
	start, end := paginate(total, opts.Offset, opts.Limit)
	return all[start:end], total, nil
}

func (s *MemoryStore) CreateSession(sess *types.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[sess.SessionID]; exists {
		return fmt.Errorf("session %s already exists", sess.SessionID)
	}
	s.sessions[sess.SessionID] = sess
	return nil
}

func (s *MemoryStore) GetSession(id string) (*types.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session %s not found", id)
	}
	return sess, nil
}

func (s *MemoryStore) UpdateSession(id string, update SessionUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[id]
	if !ok {
		return fmt.Errorf("session %s not found", id)
	}

	if update.Status != "" {
		sess.Status = update.Status
	}
	if update.CompletedAt != "" {
		sess.CompletedAt = update.CompletedAt
	}
	if update.LastHeartbeat != "" {
		sess.LastHeartbeat = update.LastHeartbeat
	}
	if update.ResultID != "" {
		sess.ResultID = update.ResultID
	}
	return nil
}

func (s *MemoryStore) CountActiveSessions(contractID string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, sess := range s.sessions {
		if sess.ContractID == contractID && sess.Status == types.SessionActive {
			count++
		}
	}
	return count, nil
}

func (s *MemoryStore) ListSessions(opts ListOptions) ([]*types.Session, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var all []*types.Session
	for _, sess := range s.sessions {
		if opts.Status != "" && sess.Status != opts.Status {
			continue
		}
		all = append(all, sess)
	}

	total := len(all)
	start := opts.Offset
	if start > total {
		start = total
	}
	end := start + opts.Limit
	if end > total {
		end = total
	}
	if opts.Limit <= 0 {
		end = total
	}
	return all[start:end], total, nil
}

func (s *MemoryStore) StoreResult(r *types.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.results[r.SessionID] = r
	s.resultsByID[r.ResultID] = r
	return nil
}

func (s *MemoryStore) GetResult(sessionID string) (*types.Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.results[sessionID]
	if !ok {
		return nil, fmt.Errorf("result for session %s not found", sessionID)
	}
	return r, nil
}

func (s *MemoryStore) GetResultByID(resultID string) (*types.Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.resultsByID[resultID]
	if !ok {
		return nil, fmt.Errorf("result %s not found", resultID)
	}
	return r, nil
}

func (s *MemoryStore) AppendEvent(e *types.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.auditEvents = append(s.auditEvents, e)
	return nil
}

func (s *MemoryStore) GetEvents(opts EventListOptions) ([]*types.AuditEvent, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*types.AuditEvent
	for _, e := range s.auditEvents {
		if opts.EventType != "" && e.EventType != opts.EventType {
			continue
		}
		if opts.SessionID != "" {
			if e.Subject == nil || e.Subject.SessionID != opts.SessionID {
				continue
			}
		}
		if opts.ContractID != "" {
			if e.Subject == nil || e.Subject.ContractID != opts.ContractID {
				continue
			}
		}
		if opts.Since != "" && e.Timestamp < opts.Since {
			continue
		}
		filtered = append(filtered, e)
	}

	total := len(filtered)
	start, end := paginate(total, opts.Offset, opts.Limit)
	return filtered[start:end], total, nil
}

// paginate returns start/end indices for a slice given offset and limit.
func paginate(total, offset, limit int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	if limit <= 0 || limit > 1000 {
		limit = 100 // default page size
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return offset, end
}
