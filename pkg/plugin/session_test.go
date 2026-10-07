package plugin

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIdentityForSessionAttachesCachedSecret(t *testing.T) {
	cache := NewSessionCache()
	defer cache.Close()

	encoded := (&Fido2HmacIdentity{
		Version: 2,
		Salt:    make([]byte, 32),
		CredId:  make([]byte, 50),
	}).String()
	want := bytes.Repeat([]byte{0x42}, 32)
	if _, err := cache.Load(encoded, func() ([]byte, error) { return want, nil }); err != nil {
		t.Fatalf("Load: %v", err)
	}

	server := &SessionServer{cache: cache}
	identity, err := server.identityForSession(encoded, nil)
	if err != nil {
		t.Fatalf("identityForSession: %v", err)
	}
	if !bytes.Equal(identity.secretKey, want) {
		t.Fatal("identity did not receive the cached secret")
	}
	if err := identity.LoadSecret(""); err != nil {
		t.Fatalf("cached identity tried to use a device: %v", err)
	}
}

func TestNewSessionServerRejectsNonSocketPath(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "session.sock")
	if err := os.WriteFile(socketPath, []byte("keep me"), 0o600); err != nil {
		t.Fatalf("create sentinel: %v", err)
	}

	_, err := NewSessionServer(socketPath, []byte("capability"), NewSessionCache())
	if err == nil {
		t.Fatal("NewSessionServer accepted a regular file as its socket path")
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("unexpected error: %v", err)
	}
	contents, readErr := os.ReadFile(socketPath)
	if readErr != nil {
		t.Fatalf("sentinel was removed: %v", readErr)
	}
	if string(contents) != "keep me" {
		t.Fatalf("sentinel changed: %q", contents)
	}
}

func TestSessionServerCloseRemovesSocket(t *testing.T) {
	// t.TempDir includes the test name and can exceed macOS's Unix socket limit.
	directory, err := os.MkdirTemp("", "fido-session-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "session.sock")
	server, err := NewSessionServer(socketPath, []byte("capability"), NewSessionCache())
	if err != nil {
		t.Fatalf("NewSessionServer: %v", err)
	}

	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve() }()
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-serveDone; err != nil {
		t.Fatalf("Serve after Close: %v", err)
	}
	if _, err := os.Stat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket path still exists: %v", err)
	}
}

type sessionReadObserver struct {
	net.Conn
	reads chan struct{}
}

func (c *sessionReadObserver) Read(p []byte) (int, error) {
	c.reads <- struct{}{}
	return c.Conn.Read(p)
}

type sessionObservedListener struct {
	net.Listener
	reads chan struct{}
}

func (l *sessionObservedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &sessionReadObserver{Conn: conn, reads: l.reads}, nil
}

func TestSessionCloseDisconnectsIdleClients(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		name := "handshake"
		if authenticated {
			name = "protocol"
		}
		t.Run(name, func(t *testing.T) {
			// Keep the path below Unix socket length limits on macOS as well.
			dir, err := os.MkdirTemp("", "fido-session-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			cache := NewSessionCache()
			secret := bytes.Repeat([]byte{0x42}, 32)
			if _, err := cache.Load("identity", func() ([]byte, error) { return secret, nil }); err != nil {
				t.Fatal(err)
			}
			capability := bytes.Repeat([]byte{0x24}, 32)
			server, err := NewSessionServer(filepath.Join(dir, "session.sock"), capability, cache)
			if err != nil {
				t.Fatal(err)
			}
			reads := make(chan struct{}, 8)
			server.listener = &sessionObservedListener{Listener: server.listener, reads: reads}
			served := make(chan error, 1)
			go func() { served <- server.Serve() }()
			conn, err := net.Dial("unix", server.SocketPath())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close(); _ = server.Close() })
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			readCount := 1
			if authenticated {
				if _, err := io.WriteString(conn, sessionHandshakeText); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.Write(capability); err != nil {
					t.Fatal(err)
				}
				// Handshake, capability, then the first age protocol read.
				readCount = 3
			}
			for range readCount {
				select {
				case <-reads:
				case <-time.After(5 * time.Second):
					t.Fatal("handler did not reach the idle read")
				}
			}
			closed := make(chan error, 1)
			go func() { closed <- server.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close waited for an idle client")
			}
			if !bytes.Equal(secret, make([]byte, len(secret))) {
				t.Fatal("Close retained the cached secret")
			}
			if _, ok := cache.Get("identity"); ok {
				t.Fatal("closed cache still serves an identity")
			}
			if !bytes.Equal(server.capability, make([]byte, len(capability))) {
				t.Fatal("Close retained the session capability")
			}
			if err := <-served; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type sessionDelayedListener struct {
	net.Listener
	accepted chan struct{}
	release  chan struct{}
}

func (l *sessionDelayedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	close(l.accepted)
	<-l.release
	return conn, nil
}

func TestSessionCloseRejectsLateAccept(t *testing.T) {
	dir, err := os.MkdirTemp("", "fido-session-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	server, err := NewSessionServer(filepath.Join(dir, "session.sock"), []byte("capability"), nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := &sessionDelayedListener{
		Listener: server.listener,
		accepted: make(chan struct{}),
		release:  make(chan struct{}),
	}
	server.listener = listener
	served := make(chan error, 1)
	go func() { served <- server.Serve() }()
	conn, err := net.Dial("unix", server.SocketPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); _ = server.Close() })
	select {
	case <-listener.accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept the connection")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	close(listener.release)
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve started a handler after shutdown")
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late accepted connection remained open: %v", err)
	}
}
