package ner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"time"
	"unicode/utf8"
)

// maxLineBytes bounds one answer line, so a misbehaving sidecar cannot
// make veil buffer without limit.
const maxLineBytes = 16 << 20

// Span is one entity the sidecar found: UTF-8 byte offsets into its unit
// and the model's label.
type Span struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Label string `json:"label"`
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

type initializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	Model           Model  `json:"model"`
}

type recognizeResult struct {
	Spans [][]Span `json:"spans"`
}

// exchange runs one initialize and one recognize on a fresh connection,
// all before deadline, and returns the validated spans of each unit, with
// overlapping or touching spans joined into one.
func (d *Detector) exchange(deadline time.Time, units []string) ([][]Span, error) {
	if err := checkSocket(d.cfg.Socket); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", d.cfg.Socket)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %v", ErrTimeout, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	c := &rpcConn{conn: conn, r: bufio.NewReaderSize(conn, 64<<10), deadline: deadline}

	var init initializeResult
	if err := c.call(1, "initialize", map[string]string{"protocolVersion": ProtocolVersion}, &init); err != nil {
		return nil, err
	}
	if init.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("%w: protocol version %q", ErrProtocol, init.ProtocolVersion)
	}
	if init.Model != d.cfg.Model {
		return nil, ErrModelMismatch
	}

	var rec recognizeResult
	if err := c.call(2, "recognize", map[string][]string{"units": units}, &rec); err != nil {
		return nil, err
	}
	if len(rec.Spans) != len(units) {
		return nil, fmt.Errorf("%w: %d span lists for %d units", ErrProtocol, len(rec.Spans), len(units))
	}
	for i, spans := range rec.Spans {
		if len(spans) > MaxSpansPerUnit {
			return nil, fmt.Errorf("%w: %d spans in one unit, more than %d", ErrProtocol, len(spans), MaxSpansPerUnit)
		}
		for _, sp := range spans {
			if err := d.validSpan(units[i], sp); err != nil {
				return nil, err
			}
		}
		rec.Spans[i] = joinSpans(spans)
	}
	return rec.Spans, nil
}

// joinSpans returns spans with every run of overlapping or touching spans
// joined into one, ordered by start. Replacing two overlapping names one
// at a time would leave part of one in clear ("Ana Ruiz" and "Ruiz López"
// in "Ana Ruiz López"). A joined span takes the label of its longest
// member (the earliest on a tie).
func joinSpans(spans []Span) []Span {
	if len(spans) < 2 {
		return spans
	}
	sorted := append([]Span(nil), spans...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		return sorted[i].End > sorted[j].End
	})
	out := []Span{sorted[0]}
	longest := sorted[0].End - sorted[0].Start
	for _, sp := range sorted[1:] {
		last := &out[len(out)-1]
		if sp.Start > last.End {
			out = append(out, sp)
			longest = sp.End - sp.Start
			continue
		}
		if n := sp.End - sp.Start; n > longest {
			last.Label, longest = sp.Label, n
		}
		if sp.End > last.End {
			last.End = sp.End
		}
	}
	return out
}

// validSpan checks that sp names a non-empty run of whole characters
// inside unit, with a label veil asked for.
func (d *Detector) validSpan(unit string, sp Span) error {
	switch {
	case sp.Start < 0 || sp.End > len(unit) || sp.Start >= sp.End:
		return fmt.Errorf("%w: span [%d,%d) outside a %d-byte unit", ErrProtocol, sp.Start, sp.End, len(unit))
	case !utf8.RuneStart(unit[sp.Start]) || (sp.End < len(unit) && !utf8.RuneStart(unit[sp.End])):
		return fmt.Errorf("%w: span [%d,%d) splits a character", ErrProtocol, sp.Start, sp.End)
	}
	if _, ok := d.cfg.Labels[sp.Label]; !ok {
		return fmt.Errorf("%w: label not requested", ErrProtocol)
	}
	return nil
}

type rpcConn struct {
	conn     net.Conn
	r        *bufio.Reader
	deadline time.Time
}

// call sends one request line and decodes the result of its answer
// into out.
func (c *rpcConn) call(id int, method string, params, out any) error {
	line, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("%w: encode %s: %v", ErrProtocol, method, err)
	}
	if _, err := c.conn.Write(append(line, '\n')); err != nil {
		return transportError(err)
	}
	answer, err := c.readLine()
	if err != nil {
		return err
	}
	// Decoding a long answer can outlast the connection's deadline, which
	// only bounds reads: wait for it no longer than the deadline. A late
	// decode finishes in the background into a result nobody reads.
	done := make(chan error, 1)
	go func() { done <- decodeAnswer(answer, id, method, out) }()
	timer := time.NewTimer(time.Until(c.deadline))
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("%w: %s answer not decoded before the deadline", ErrTimeout, method)
	}
}

// decodeAnswer checks one answer line and decodes its result into out.
func decodeAnswer(answer []byte, id int, method string, out any) error {
	var resp rpcResponse
	if err := json.Unmarshal(answer, &resp); err != nil {
		return fmt.Errorf("%w: %s answer is not JSON", ErrProtocol, method)
	}
	switch {
	case resp.JSONRPC != "2.0":
		return fmt.Errorf("%w: %s answer is not JSON-RPC 2.0", ErrProtocol, method)
	case !bytes.Equal(bytes.TrimSpace(resp.ID), []byte(fmt.Sprint(id))):
		return fmt.Errorf("%w: %s answer has another id", ErrProtocol, method)
	case len(resp.Error) > 0 && !bytes.Equal(resp.Error, []byte("null")):
		return fmt.Errorf("%w: %s answered with an error", ErrProtocol, method)
	case len(resp.Result) == 0 || bytes.Equal(resp.Result, []byte("null")):
		return fmt.Errorf("%w: %s answer has no result", ErrProtocol, method)
	}
	if err := json.Unmarshal(resp.Result, out); err != nil {
		return fmt.Errorf("%w: %s result is malformed", ErrProtocol, method)
	}
	return nil
}

// readLine reads one answer line of at most maxLineBytes.
func (c *rpcConn) readLine() ([]byte, error) {
	var line []byte
	for {
		chunk, err := c.r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxLineBytes {
			return nil, fmt.Errorf("%w: answer longer than %d bytes", ErrProtocol, maxLineBytes)
		}
		switch {
		case err == nil:
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		default:
			return nil, transportError(err)
		}
	}
}

// transportError classifies a read or write failure: the deadline
// passing is a timeout, the peer going away is a crash.
func transportError(err error) error {
	var ne net.Error
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	default:
		// io.EOF, ECONNRESET, EPIPE and any other failure of an open
		// connection: the sidecar went away mid-exchange.
		return fmt.Errorf("%w: %v", ErrCrashed, err)
	}
}
