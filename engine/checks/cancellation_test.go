package checks

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tarpit accepts connections and never sends anything, like a hung service.
// It reports on closed whenever a client hangs up.
func tarpit(t *testing.T) (port int, closed <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	ch := make(chan struct{}, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 1024)
				for {
					if _, err := conn.Read(buf); err != nil {
						_ = conn.Close()
						ch <- struct{}{}
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, ch
}

// Checks against a server that never responds must time out on schedule and
// actually hang up, instead of leaving the check blocked on the connection.
func TestChecks_CancelTearsDownHungConnection(t *testing.T) {
	creds := []TaskCredential{{Username: "user", Password: "pass"}}
	svc := func(port int) Service {
		return Service{Name: "hung", Target: "127.0.0.1", Port: port, Timeout: 1, CredLists: []string{"creds"}, TaskCredentials: creds}
	}

	tests := []struct {
		name  string
		check func(port int) Runner
	}{
		{"ssh", func(p int) Runner { return &Ssh{Service: svc(p), Command: []commandData{{Command: "true"}}} }},
		{"ftp", func(p int) Runner { return &Ftp{Service: svc(p)} }},
		{"smtp", func(p int) Runner { return &Smtp{Service: svc(p)} }},
		{"imap", func(p int) Runner { return &Imap{Service: svc(p)} }},
		{"pop3", func(p int) Runner { return &Pop3{Service: svc(p)} }},
		{"vnc", func(p int) Runner { return &Vnc{Service: svc(p)} }},
		{"ldap", func(p int) Runner { return &Ldap{Service: svc(p), Domain: "example.com"} }},
		{"smb", func(p int) Runner { return &Smb{Service: svc(p)} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, closed := tarpit(t)
			results := make(chan Result, 1)

			start := time.Now()
			tt.check(port).Run(context.Background(), 1, "01", 1, results)
			res := <-results
			assert.False(t, res.Status)
			assert.Less(t, time.Since(start), 3*time.Second, "check overran its timeout")

			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("check never closed its connection to the hung server")
			}
		})
	}
}

// Cancelling the caller's context (e.g. the round ending) stops the check
// even if its own timeout hasn't passed.
func TestServiceRun_ParentCancelStopsCheck(t *testing.T) {
	port, closed := tarpit(t)
	ssh := &Ssh{Service: Service{Name: "ssh", Target: "127.0.0.1", Port: port, Timeout: 30, TaskCredentials: []TaskCredential{{Username: "u", Password: "p"}}}}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	results := make(chan Result, 1)
	start := time.Now()
	ssh.Run(ctx, 1, "01", 1, results)
	res := <-results
	assert.False(t, res.Status)
	assert.Equal(t, "check timeout exceeded", res.Error)
	assert.Less(t, time.Since(start), 2*time.Second)

	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("check never closed its connection after parent cancel")
	}
}

func TestRunSubchecks_StopsWhenContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	items := []commandData{{Command: "1"}, {Command: "2"}, {Command: "3"}}

	ran := 0
	res := RunSubchecks(ctx, items, true, Result{}, "suffix", func(item commandData, res Result) Result {
		ran++
		cancel() // simulate the timeout landing during the first subcheck
		res.Status = true
		return res
	})

	assert.Equal(t, 1, ran)
	assert.False(t, res.Status)
	assert.Equal(t, "check timeout exceeded", res.Error)
	assert.Equal(t, "ran out of time after 1 of 3 checks (suffix)", res.Debug)
}

func TestServiceRun_ContextCancelledOnTimeout(t *testing.T) {
	svc := &Service{Name: "slow", Timeout: 1}
	results := make(chan Result, 1)
	sawCancel := make(chan struct{})

	start := time.Now()
	svc.Run(context.Background(), 1, "1", 1, results, func(ctx context.Context, teamID uint, teamIdentifier string, checkResult Result, response chan Result) {
		<-ctx.Done()
		close(sawCancel)
		response <- checkResult
	})
	res := <-results
	assert.Equal(t, "check timeout exceeded", res.Error)

	select {
	case <-sawCancel:
		assert.Less(t, time.Since(start), 2*time.Second)
	case <-time.After(3 * time.Second):
		t.Fatal("check's context was not cancelled at its timeout")
	}
}

func TestServiceRun_ResultWinsOverLateCancel(t *testing.T) {
	// A check that responds and returns must have its result reported, even
	// though returning cancels ctx (both select cases become ready).
	for i := range 200 {
		svc := &Service{Name: "fast", Timeout: 5}
		results := make(chan Result, 1)
		svc.Run(context.Background(), 1, "1", 1, results, func(ctx context.Context, teamID uint, teamIdentifier string, checkResult Result, response chan Result) {
			checkResult.Status = true
			response <- checkResult
		})
		res := <-results
		require.True(t, res.Status, "iteration "+strconv.Itoa(i))
	}
}
