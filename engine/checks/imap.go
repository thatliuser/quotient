package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

type Imap struct {
	Service
	Domain    string
	Encrypted bool
}

func (c Imap) Run(ctx context.Context, teamID uint, teamIdentifier string, roundID uint, resultsChan chan Result) {
	definition := func(ctx context.Context, teamID uint, teamIdentifier string, checkResult Result, response chan Result) {
		// Connect to server with TLS or not
		var cl *client.Client
		conn, err := dialContext(ctx, "tcp", fmt.Sprintf("%s:%d", c.Target, c.Port))
		if err == nil && c.Encrypted {
			tlsConn := tls.Client(conn, &tls.Config{ServerName: c.Target}) // #nosec G402 -- competition services may use self-signed certs
			if err = tlsConn.HandshakeContext(ctx); err == nil {
				conn = tlsConn
			}
		}
		if err == nil {
			cl, err = client.New(conn)
		}
		if err != nil {
			checkResult.Error = "connection to server failed"
			checkResult.Debug = err.Error()
			response <- checkResult
			return
		}
		defer func() {
			if err := cl.Close(); err != nil {
				slog.Error("failed to close imap client", "error", err)
			}
		}()

		if len(c.CredLists) > 0 {
			username, password, err := c.getCreds(teamID)
			if err != nil {
				checkResult.Error = "error getting creds"
				checkResult.Debug = err.Error()
				response <- checkResult
				return
			}

			// Set timeout for commands
			cl.Timeout = time.Duration(c.Timeout) * time.Second
			if c.Domain != "" {
				username = username + c.Domain
			}

			// Login
			err = cl.Login(username, password)
			if err != nil {
				checkResult.Error = "login failed"
				checkResult.Debug = "creds " + username + ":" + password + ", error: " + err.Error()
				response <- checkResult
				return
			}
			// nolint:errcheck
			defer cl.Logout()

			// List mailboxes
			mailboxes := make(chan *imap.MailboxInfo, 10)
			err = cl.List("", "*", mailboxes)
			if err != nil {
				checkResult.Error = "listing mailboxes failed"
				checkResult.Debug = err.Error()
				response <- checkResult
				return
			}
			checkResult.Status = true
			checkResult.Debug = "mailbox listed successfully with creds " + username + ":" + password
			response <- checkResult
			return
		}
		checkResult.Status = true
		checkResult.Debug = "smtp server responded to request (anonymous)"
		response <- checkResult
	}

	c.Service.Run(ctx, teamID, teamIdentifier, roundID, resultsChan, definition)
}

func (c *Imap) Verify(box string, ip string, points int, timeout int, slapenalty int, slathreshold int) error {
	if c.ServiceType == "" {
		c.ServiceType = "Imap"
	}
	if err := c.Configure(ip, points, timeout, slapenalty, slathreshold); err != nil {
		return err
	}
	if c.Port == 0 {
		c.Port = 143
	}
	if c.Display == "" {
		c.Display = "imap"
	}
	if c.Name == "" {
		c.Name = box + "-" + c.Display
	}

	return nil
}
