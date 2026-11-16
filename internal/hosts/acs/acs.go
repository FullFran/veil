// Package acs serves the OWASP Agent Control Standard: veil as the
// Guardian Agent an Observed Agent asks before each step. It owns only
// what does not depend on the ACS version (the stdio transport and the
// dispatch by acs_version); everything about one wire version lives in a
// sibling package (v0_1) behind the port contract.
//
// Adding ACS version X.Y is a sibling package vX_Y with its own vendored,
// digest-pinned spec and one entry in versions below.
package acs

import (
	"encoding/json"
	"slices"
	"sync"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/hosts/acs/v0_1"
	"github.com/FullFran/veil/internal/problem"
)

// versions maps every acs_version veil speaks to its answerer. Only an
// exact match dispatches: ACS 0.1.x patch releases rewrite the schemas in
// place, so veil never assumes another version shares the pinned one.
var versions = map[string]func(port.Config) port.Version{
	v0_1.Version: v0_1.New,
}

// rpcUnsupportedVersion is ACS UNSUPPORTED_VERSION (Specification 17.1).
const rpcUnsupportedVersion = -32001

// SupportedVersions lists the ACS versions veil speaks, sorted.
func SupportedVersions() []string {
	out := make([]string, 0, len(versions))
	for v := range versions {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// Server answers ACS messages of every version veil speaks. Each version's
// answerer is created once, so per-session state such as seen request_ids
// lasts as long as the server.
type Server struct {
	cfg     port.Config
	mu      sync.Mutex
	answers map[string]port.Version
}

// NewServer returns a server for cfg.
func NewServer(cfg port.Config) *Server {
	return &Server{cfg: cfg, answers: map[string]port.Version{}}
}

// Answer answers one JSON-RPC message by its params.acs_version. A message
// that is not JSON is -32700; a batch or a message without a string
// acs_version is -32600; a version veil has no package for is -32001 with
// data.supported_versions.
func (s *Server) Answer(msg []byte) port.Reply {
	var doc any
	if err := domain.DecodeJSON(msg, &doc); err != nil {
		return port.ErrorReply(nil, port.RPCParseError, problem.InputInvalid, nil)
	}
	obj, ok := doc.(map[string]any)
	if !ok {
		return port.ErrorReply(nil, port.RPCInvalidRequest, problem.ACSRequestInvalid, nil)
	}
	id, _ := json.Marshal(obj["id"])
	params, _ := obj["params"].(map[string]any)
	version, ok := params["acs_version"].(string)
	if !ok {
		return port.ErrorReply(id, port.RPCInvalidRequest, problem.ACSRequestInvalid, nil)
	}
	answerer := s.answerer(version)
	if answerer == nil {
		return port.ErrorReply(id, rpcUnsupportedVersion, problem.ACSVersionUnsupported,
			map[string]any{"supported_versions": SupportedVersions()})
	}
	return answerer.Answer(msg)
}

func (s *Server) answerer(version string) port.Version {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.answers[version]; ok {
		return a
	}
	newVersion, ok := versions[version]
	if !ok {
		return nil
	}
	a := newVersion(s.cfg)
	s.answers[version] = a
	return a
}
