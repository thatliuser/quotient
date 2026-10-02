package checks

import (
	"context"
	"strconv"
	// why are there no good rdp libraries?
)

type Rdp struct {
	Service
}

func (c Rdp) Run(ctx context.Context, teamID uint, teamIdentifier string, roundID uint, resultsChan chan Result) {
	definition := func(ctx context.Context, teamID uint, teamIdentifier string, checkResult Result, response chan Result) {
		conn, err := dialContext(ctx, "tcp", c.Target+":"+strconv.Itoa(c.Port))
		if err != nil {
			checkResult.Error = "connection error"
			checkResult.Debug = err.Error()
			response <- checkResult
			return
		}
		_ = conn.Close()
		checkResult.Status = true
		response <- checkResult
	}

	c.Service.Run(ctx, teamID, teamIdentifier, roundID, resultsChan, definition)
}

func (c *Rdp) Verify(box string, ip string, points int, timeout int, slapenalty int, slathreshold int) error {
	if c.ServiceType == "" {
		c.ServiceType = "Rdp"
	}
	if err := c.Configure(ip, points, timeout, slapenalty, slathreshold); err != nil {
		return err
	}
	if c.Display == "" {
		c.Display = "rdp"
	}
	if c.Name == "" {
		c.Name = box + "-" + c.Display
	}
	if c.Port == 0 {
		c.Port = 3389
	}

	return nil
}
