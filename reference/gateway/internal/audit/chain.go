// Package audit implements the DSSP Merkle-chained audit ledger.
//
// Each audit event includes a hash computed over its canonical JSON form
// (excluding the event_hash field), plus a reference to the previous event's
// hash. This creates a tamper-evident chain: modifying any event invalidates
// all subsequent hashes.
//
// The chain uses SHA-256 as the baseline hash algorithm, per the spec.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/dssp-protocol/gateway/internal/canonical"
	"github.com/dssp-protocol/gateway/internal/types"
	"github.com/google/uuid"
)

type Chain struct {
	mu             sync.Mutex
	sequenceNumber int64
	lastEventHash  *types.HashDigest
}

func NewChain() *Chain {
	return &Chain{
		sequenceNumber: 0,
		lastEventHash:  nil,
	}
}

func makeEventID() string {
	return fmt.Sprintf("%s-%s", types.PrefixEvent, hex.EncodeToString(uuid.New().NodeID()))
}

// NewEvent creates a properly sequenced and hashed audit event.
// The chain manages sequence numbers, previous event hashes, and event hashes.
func (c *Chain) NewEvent(
	eventType string,
	actor types.AuditActor,
	subject *types.AuditSubject,
	action map[string]interface{},
	outcome types.AuditOutcome,
) (*types.AuditEvent, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	event := &types.AuditEvent{
		Schema:         types.SchemaAuditEvent,
		DSPVersion:     types.DSPVersion,
		EventID:        makeEventID(),
		SequenceNumber: c.sequenceNumber,
		Timestamp:      types.NowUTC(),
		EventType:      eventType,
		Actor:          actor,
		Subject:        subject,
		Action:         action,
		Outcome:        outcome,
		GatewayReceivedAt: types.NowUTC(),
	}

	if c.lastEventHash != nil {
		event.PreviousEventHash = c.lastEventHash
	}

	hash, err := computeEventHash(event)
	if err != nil {
		return nil, fmt.Errorf("audit: compute event hash: %w", err)
	}
	event.EventHash = *hash

	c.lastEventHash = hash
	c.sequenceNumber++

	return event, nil
}

func (c *Chain) NewViolationEvent(
	eventType string,
	actor types.AuditActor,
	subject *types.AuditSubject,
	action map[string]interface{},
	outcome types.AuditOutcome,
	violation *types.ViolationDetails,
) (*types.AuditEvent, error) {
	event, err := c.NewEvent(eventType, actor, subject, action, outcome)
	if err != nil {
		return nil, err
	}

	// Re-lock to update the event and recompute the hash with violation data.
	c.mu.Lock()
	defer c.mu.Unlock()

	event.ViolationDetails = violation

	hash, err := computeEventHash(event)
	if err != nil {
		return nil, fmt.Errorf("audit: recompute event hash with violation: %w", err)
	}
	event.EventHash = *hash
	c.lastEventHash = hash

	return event, nil
}

func (c *Chain) SequenceNumber() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sequenceNumber
}

// VerifyChain checks the integrity of a sequence of events: monotonic sequence
// numbers, correct event hashes, and valid previous_event_hash linkage.
func VerifyChain(events []*types.AuditEvent, expectedStart int64) error {
	for i, event := range events {
		expectedSeq := expectedStart + int64(i)
		if event.SequenceNumber != expectedSeq {
			return fmt.Errorf("audit: event %d has sequence %d, expected %d",
				i, event.SequenceNumber, expectedSeq)
		}

		computed, err := computeEventHash(event)
		if err != nil {
			return fmt.Errorf("audit: event %d hash computation failed: %w", i, err)
		}
		if computed.Value != event.EventHash.Value {
			return fmt.Errorf("audit: event %d hash mismatch: computed %s, stored %s",
				i, computed.Value, event.EventHash.Value)
		}

		if i == 0 {
			continue // Genesis event or start of verification window.
		}
		prevHash := events[i-1].EventHash
		if event.PreviousEventHash == nil {
			return fmt.Errorf("audit: event %d missing previous_event_hash", i)
		}
		if event.PreviousEventHash.Value != prevHash.Value {
			return fmt.Errorf("audit: event %d previous_event_hash mismatch: stored %s, expected %s",
				i, event.PreviousEventHash.Value, prevHash.Value)
		}
	}
	return nil
}

// computeEventHash computes the SHA-256 hash of an event's canonical JSON form,
// excluding the event_hash field itself.
func computeEventHash(event *types.AuditEvent) (*types.HashDigest, error) {
	b, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("marshal event: %w", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("unmarshal event map: %w", err)
	}
	delete(m, "event_hash")

	canonBytes, err := canonical.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("canonicalize event: %w", err)
	}

	h := sha256.Sum256(canonBytes)
	return &types.HashDigest{
		Algorithm: "sha-256",
		Value:     hex.EncodeToString(h[:]),
	}, nil
}

func HashData(data interface{}) (*types.HashDigest, error) {
	canonBytes, err := canonical.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("canonicalize data: %w", err)
	}
	h := sha256.Sum256(canonBytes)
	return &types.HashDigest{
		Algorithm: "sha-256",
		Value:     hex.EncodeToString(h[:]),
	}, nil
}

func SystemActor() types.AuditActor {
	return types.AuditActor{Type: "system"}
}

func GatewayActor() types.AuditActor {
	return types.AuditActor{Type: "gateway"}
}

func AgentActor(orgID, agentID string) types.AuditActor {
	return types.AuditActor{
		Type:    "agent",
		OrgID:   orgID,
		AgentID: agentID,
	}
}

func OwnerActor(orgID string) types.AuditActor {
	return types.AuditActor{
		Type:  "owner",
		OrgID: orgID,
	}
}

func SuccessOutcome() types.AuditOutcome {
	return types.AuditOutcome{Status: "success"}
}

func FailureOutcome(code, message string) types.AuditOutcome {
	return types.AuditOutcome{
		Status:       "failure",
		ErrorCode:    code,
		ErrorMessage: message,
	}
}

func DeniedOutcome(reason string) types.AuditOutcome {
	return types.AuditOutcome{
		Status:       "denied",
		ErrorMessage: reason,
	}
}
