package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/FullFran/veil/internal/domain"
	"github.com/FullFran/veil/internal/hosts/acs"
	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/problem"
)

// The ACS HMAC secret is configured out of band, like the store key:
// VEIL_ACS_KEY_ID names it, and its bytes (base64) come from the inherited
// descriptor VEIL_ACS_KEY_FD or the systemd credential veil-acs-key. Only
// the descriptor number travels in the environment, never the secret.
const (
	acsKeyIDEnv       = "VEIL_ACS_KEY_ID"
	acsKeyFDEnv       = "VEIL_ACS_KEY_FD"
	acsCredentialName = "veil-acs-key"
	// acsMinSecretBytes is the shortest secret veil accepts: the HMAC-SHA256
	// output size, as ACS Specification section 10 requires.
	acsMinSecretBytes = 32
	acsMaxSecretRead  = 64 << 10
)

var errACSKey = errors.New("veil: ACS secret configuration is invalid")

// loadACSSecret reads the ACS secret configuration. Nothing configured is
// no secret (unsigned requests only); a key id without a secret, a secret
// without a key id, or an unreadable, non-base64 or short secret is an
// error, so the acs mode fails closed instead of running unsigned.
func loadACSSecret(getenv func(string) string) (*port.Secret, error) {
	keyID := getenv(acsKeyIDEnv)
	raw, found, err := readACSSecret(getenv)
	if err != nil {
		return nil, err
	}
	switch {
	case keyID == "" && !found:
		return nil, nil
	case keyID == "" || !found:
		return nil, fmt.Errorf("%w: %s and the secret must be set together", errACSKey, acsKeyIDEnv)
	}
	secret, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil {
		return nil, fmt.Errorf("%w: the secret is not base64", errACSKey)
	}
	if len(secret) < acsMinSecretBytes {
		return nil, fmt.Errorf("%w: the secret is shorter than %d bytes", errACSKey, acsMinSecretBytes)
	}
	return &port.Secret{KeyID: keyID, Bytes: secret}, nil
}

func readACSSecret(getenv func(string) string) ([]byte, bool, error) {
	if v := getenv(acsKeyFDEnv); v != "" {
		fd, err := strconv.Atoi(v)
		if err != nil || fd < 3 {
			// 0, 1 and 2 are stdio: fd 0 would consume the ACS stream.
			return nil, false, fmt.Errorf("%w: %s must be a descriptor number of 3 or higher", errACSKey, acsKeyFDEnv)
		}
		f := os.NewFile(uintptr(fd), acsKeyFDEnv)
		if f == nil {
			return nil, false, fmt.Errorf("%w: %s is not a valid descriptor", errACSKey, acsKeyFDEnv)
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, acsMaxSecretRead))
		if err != nil {
			return nil, false, fmt.Errorf("%w: %s cannot be read", errACSKey, acsKeyFDEnv)
		}
		return raw, true, nil
	}
	if dir := getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		raw, err := os.ReadFile(filepath.Join(dir, acsCredentialName))
		switch {
		case err == nil:
			return raw, true, nil
		case !errors.Is(err, fs.ErrNotExist):
			return nil, false, fmt.Errorf("%w: credential %s cannot be read", errACSKey, acsCredentialName)
		}
	}
	return nil, false, nil
}

// runACS serves the OWASP Agent Control Standard on stdio: veil is the
// Guardian an Observed Agent asks before each tool call. Each message is
// answered on stdout; each answer that is not a decision also writes one
// problem line on stderr, and the exit code is 1 if any did. When veil
// cannot evaluate (invalid secret configuration or policy) it still
// answers: hooks are denied and handshakes refused, never allowed.
func runACS(stdin io.Reader, stdout, stderr io.Writer) int {
	cfg := port.Config{}
	secret, err := loadACSSecret(os.Getenv)
	if err != nil {
		cfg.Unavailable = problem.ACSKeyInvalid
	} else {
		cfg.Secret = secret
		e, err := newEngine()
		if err != nil {
			cfg.Unavailable = classifyPolicyError(err)
		} else {
			cfg.Guard = func(event domain.Event) (domain.Decision, json.RawMessage, problem.Code) {
				return e.decide(domain.HostACS, event)
			}
		}
	}

	failed := false
	onFailure := func(code problem.Code) {
		problem.Write(stderr, problem.New(code))
		failed = true
	}
	if err := acs.Serve(stdin, stdout, acs.NewServer(cfg).Answer, onFailure); err != nil {
		onFailure(problem.InputInvalid)
	}
	if failed {
		return problem.ExitFailedClosed
	}
	return problem.ExitDecision
}
