package l4

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn is a WebSocket as a byte stream: each Write is one binary message and
// Read runs through messages in turn. An empty message is the end of one
// direction, so CloseWrite gives WebSockets the half-close TCP has.
type wsConn struct {
	c   *websocket.Conn
	r   io.Reader // the message being read
	got bool      // r has yielded data
	eof bool
	wmu sync.Mutex
}

func newWSConn(c *websocket.Conn) *wsConn { return &wsConn{c: c} }

func (w *wsConn) Read(p []byte) (int, error) {
	for !w.eof {
		if w.r == nil {
			typ, r, err := w.c.NextReader()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					return 0, io.EOF
				}
				return 0, err
			}
			if typ != websocket.BinaryMessage {
				continue
			}
			w.r, w.got = r, false
		}
		n, err := w.r.Read(p)
		if n > 0 {
			w.got = true
		}
		if err == io.EOF {
			w.r = nil
			if !w.got {
				w.eof = true // an empty message: the peer closed its side
				return 0, io.EOF
			}
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
	return 0, io.EOF
}

func (w *wsConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if err := w.c.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) CloseWrite() error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.c.WriteMessage(websocket.BinaryMessage, nil)
}

func (w *wsConn) Close() error {
	w.wmu.Lock()
	_ = w.c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
	w.wmu.Unlock()
	return w.c.Close()
}

func (w *wsConn) LocalAddr() net.Addr  { return w.c.LocalAddr() }
func (w *wsConn) RemoteAddr() net.Addr { return w.c.RemoteAddr() }

func (w *wsConn) SetDeadline(t time.Time) error {
	_ = w.c.SetReadDeadline(t)
	return w.c.SetWriteDeadline(t)
}
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }
