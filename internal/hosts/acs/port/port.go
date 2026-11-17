// Package port is the contract between veil's ACS dispatcher
// (internal/hosts/acs) and one ACS wire version (internal/hosts/acs/v0_1,
// and later siblings). It holds nothing ACS-version-specific: the guard
// veil decides with, the out-of-band HMAC secret, the clock, and the
// JSON-RPC 2.0 error object every version answers a refusal with.
//
// A version package imports port; port never imports a version, so a new
// ACS version is a sibling package plus one entry in the dispatcher's
// table, and dropping one is deleting its folder.
package port

import (
	"encoding/json"
	"time"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/problem"
)

// Guard decides one host-neutral event. It returns the decision and its
// evidence record (one JSON object, see internal/evidence), or the problem
// code of a failure, in which case the event must not proceed.
type Guard func(domain.Event) (domain.Decision, json.RawMessage, problem.Code)

// Secret is the pre-shared HMAC secret named by KeyID. It always comes
// from veil's configuration, never from a message.
type Secret struct {
	KeyID string
	Bytes []byte
}

// Config is what every ACS version needs to answer messages.
type Config struct {
	// Guard decides hook events. It is not called when Unavailable is set.
	Guard Guard
	// Unavailable, when set, is why veil cannot evaluate anything (for
	// example an invalid policy or secret configuration). Hooks are then
	// denied with it and handshakes refused.
	Unavailable problem.Code
	// Secret, when set, makes signatures mandatory and verifiable. When
	// nil, unsigned requests are accepted and signed ones are rejected:
	// their key_id names no configured secret.
	Secret *Secret
	// Now is the clock for timestamp checks. Nil means time.Now.
	Now func() time.Time
}

// Clock returns c.Now, or time.Now when it is nil.
func (c Config) Clock() time.Time {
	if c.Now == nil {
		return time.Now()
	}
	return c.Now()
}

// Reply is the answer to one message: the JSON-RPC response body, and the
// problem code when the message failed (a JSON-RPC error, or a deny veil
// answered because it could not decide). Failure is empty for a decision.
type Reply struct {
	Body    []byte
	Failure problem.Code
}

// Version answers messages of one ACS wire version.
type Version interface {
	Answer(msg []byte) Reply
}
