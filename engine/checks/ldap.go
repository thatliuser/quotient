package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

type Ldap struct {
	Service
	Domain    string
	Encrypted bool
}

func (c Ldap) Run(ctx context.Context, teamID uint, teamIdentifier string, roundID uint, resultsChan chan Result) {
	definition := func(ctx context.Context, teamID uint, teamIdentifier string, checkResult Result, response chan Result) {
		// Set timeout
		ldap.DefaultTimeout = time.Duration(c.Timeout) * time.Second

		username, password, err := c.getCreds(teamID)
		if err != nil {
			checkResult.Error = "error getting creds"
			checkResult.Debug = err.Error()
			response <- checkResult
			return
		}

		scheme := "ldap"
		if c.Encrypted {
			scheme = "ldaps"
		}
		lconn, err := dialLdap(ctx, scheme, c.Target, c.Port)
		if err != nil {
			checkResult.Error = "failed to connect"
			checkResult.Debug = "login " + username + " password " + password + " failed with error: " + err.Error()
			response <- checkResult
			return
		}
		defer func() {
			if err := lconn.Close(); err != nil {
				slog.Error("failed to close ldap connection", "error", err)
			}
		}()

		// Set message timeout
		lconn.SetTimeout(time.Duration(c.Timeout) * time.Second)

		// Attempt to login
		splitDomain := strings.Split(c.Domain, ".")
		if len(splitDomain) != 2 {
			checkResult.Error = "Configured domain is not valid (needs to be domain and tld)"
			response <- checkResult
			return
		}

		authString := fmt.Sprintf("%s@%s", username, c.Domain)
		err = lconn.Bind(authString, password)
		if err != nil {
			checkResult.Error = "login failed for " + username
			checkResult.Debug = "auth string " + authString + ", login " + username + " password " + password + " failed with error: " + err.Error()
			response <- checkResult
			return
		}

		checkResult.Status = true
		checkResult.Debug = "login successful for username " + username + " password " + password
		response <- checkResult
	}

	c.Service.Run(ctx, teamID, teamIdentifier, roundID, resultsChan, definition)
}

func (c *Ldap) Verify(box string, ip string, points int, timeout int, slapenalty int, slathreshold int) error {
	if c.ServiceType == "" {
		c.ServiceType = "Ldap"
	}
	if err := c.Configure(ip, points, timeout, slapenalty, slathreshold); err != nil {
		return err
	}
	if c.Port == 0 {
		c.Port = 636
	}
	if c.Display == "" {
		c.Display = "ldap"
	}
	if c.Name == "" {
		c.Name = box + "-" + c.Display
	}

	return nil
}

// dialLdap is ldap.DialURL for ldap:// and ldaps://, but cancellable via ctx.
func dialLdap(ctx context.Context, scheme string, host string, port int) (*ldap.Conn, error) {
	conn, err := dialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return nil, err
	}
	if scheme == "ldaps" {
		// Matches ldap.DialURL, which verifies the server cert against host
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		conn = tlsConn
	}
	lconn := ldap.NewConn(conn, scheme == "ldaps")
	lconn.Start()
	return lconn, nil
}
