package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"strings"
)

// upgradeWS performs the HTTP → WebSocket handshake and returns the raw conn.
func upgradeWS(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if !strings.EqualFold(r.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("not a websocket upgrade")
	}
	key := r.Header.Get("Sec-Websocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-Websocket-Key")
	}

	accept := wsAcceptKey(key)

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijack not supported")
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := buf.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := buf.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func wsAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsWriteText writes a WebSocket text frame.
func wsWriteText(conn net.Conn, data []byte) error {
	return wsWriteFrame(conn, 0x81, data)
}

// wsWritePing writes a WebSocket ping frame.
func wsWritePing(conn net.Conn) error {
	return wsWriteFrame(conn, 0x89, nil)
}

func wsWriteFrame(conn net.Conn, opcode byte, payload []byte) error {
	n := len(payload)
	var header []byte
	switch {
	case n <= 125:
		header = []byte{opcode, byte(n)}
	case n <= 65535:
		header = make([]byte, 4)
		header[0] = opcode
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:], uint16(n))
	default:
		header = make([]byte, 10)
		header[0] = opcode
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(n))
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := conn.Write(payload)
		return err
	}
	return nil
}

// wsReadLoop drains incoming frames (just reads to unblock the connection).
func wsReadLoop(conn net.Conn) {
	buf := bufio.NewReader(conn)
	for {
		// Read first two bytes: FIN+opcode, length
		b := make([]byte, 2)
		if _, err := readFull(buf, b); err != nil {
			return
		}
		opcode := b[0] & 0x0f
		masked := (b[1] & 0x80) != 0
		payloadLen := int64(b[1] & 0x7f)

		switch payloadLen {
		case 126:
			ext := make([]byte, 2)
			if _, err := readFull(buf, ext); err != nil {
				return
			}
			payloadLen = int64(binary.BigEndian.Uint16(ext))
		case 127:
			ext := make([]byte, 8)
			if _, err := readFull(buf, ext); err != nil {
				return
			}
			payloadLen = int64(binary.BigEndian.Uint64(ext))
		}

		if masked {
			mask := make([]byte, 4)
			if _, err := readFull(buf, mask); err != nil {
				return
			}
		}

		// Drain the payload
		if payloadLen > 0 {
			_, err := buf.Discard(int(payloadLen))
			if err != nil {
				return
			}
		}

		// Connection close frame
		if opcode == 0x08 {
			return
		}
	}
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		nn, err := r.Read(b[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
