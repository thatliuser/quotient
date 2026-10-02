package checks

import (
	"context"
	"errors"
	"strconv"
)

type Tcp struct {
	Service
}

func (c Tcp) Run(ctx context.Context, teamID uint, teamIdentifier string, roundID uint, resultsChan chan Result) {
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
		checkResult.Debug = "responded to request"
		response <- checkResult
	}

	c.Service.Run(ctx, teamID, teamIdentifier, roundID, resultsChan, definition)
}

func (c *Tcp) Verify(box string, ip string, points int, timeout int, slapenalty int, slathreshold int) error {
	if c.ServiceType == "" {
		c.ServiceType = "Tcp"
	}
	if err := c.Configure(ip, points, timeout, slapenalty, slathreshold); err != nil {
		return err
	}
	if c.Display == "" {
		c.Display = "tcp"
	}
	if c.Name == "" {
		c.Name = box + "-" + c.Display
	}
	if c.Port == 0 {
		return errors.New("port is required")
	}

	return nil
}
