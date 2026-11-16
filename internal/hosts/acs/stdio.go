package acs

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/FullFran/veil/internal/hosts/acs/port"
	"github.com/FullFran/veil/internal/problem"
)

// maxMessage bounds one message, framed or bare, so a peer cannot make
// veil buffer without limit.
const maxMessage = 16 << 20

// Serve answers ACS messages read from r on w. Input that starts with a
// header is a stream of Content-Length framed messages (the ACS stdio
// transport), each answered with a framed response until EOF. Otherwise
// all of r is one bare JSON message, answered on one line. onFailure is
// called with the problem code of every answer that is not a decision.
// A framing error is answered with a framed parse error and returned.
func Serve(r io.Reader, w io.Writer, answer func([]byte) port.Reply, onFailure func(problem.Code)) error {
	br := bufio.NewReader(r)
	if !framed(br) {
		msg, err := io.ReadAll(io.LimitReader(br, maxMessage+1))
		if err != nil {
			return err
		}
		if len(msg) > maxMessage {
			msg = nil // answered as a parse error below
		}
		return write(w, answer(msg), onFailure, func(body []byte) []byte { return append(body, '\n') })
	}
	for {
		msg, err := readFrame(br)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			reply := port.ErrorReply(nil, port.RPCParseError, problem.InputInvalid, nil)
			if werr := write(w, reply, func(problem.Code) {}, frameBody); werr != nil {
				return werr
			}
			return err
		}
		if err := write(w, answer(msg), onFailure, frameBody); err != nil {
			return err
		}
	}
}

// framed reports whether the input starts with a header rather than a
// JSON value. A JSON-RPC message starts with '{' (or '[' for a batch).
func framed(br *bufio.Reader) bool {
	for {
		b, err := br.Peek(1)
		if err != nil {
			return false
		}
		switch b[0] {
		case ' ', '\t', '\r', '\n':
			_, _ = br.ReadByte()
		case '{', '[':
			return false
		default:
			return true
		}
	}
}

func write(w io.Writer, reply port.Reply, onFailure func(problem.Code), wrap func([]byte) []byte) error {
	if reply.Failure != "" {
		onFailure(reply.Failure)
	}
	_, err := w.Write(wrap(reply.Body))
	return err
}

func frameBody(body []byte) []byte {
	return append([]byte("Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"), body...)
}

// readFrame reads one Content-Length framed message: header lines up to
// an empty line, then exactly Content-Length bytes. io.EOF means the
// stream ended cleanly between messages.
func readFrame(r *bufio.Reader) ([]byte, error) {
	length := -1
	for first := true; ; first = false {
		line, err := r.ReadString('\n')
		if err != nil {
			if first && line == "" && errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("acs: read header: %w", io.ErrUnexpectedEOF)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("acs: malformed header %q", line)
		}
		if strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil || n < 0 || n > maxMessage {
				return nil, fmt.Errorf("acs: invalid Content-Length %q", value)
			}
			length = n
		}
	}
	if length < 0 {
		return nil, errors.New("acs: missing Content-Length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("acs: read body: %w", err)
	}
	return body, nil
}
