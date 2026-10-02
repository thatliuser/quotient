package checks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
)

// FileDifference returns the percentage difference
// between the contents of the filename passed and
// the contents of the file passed.
func FileDifference(fileName string, fileContent string) (int, error) {
	originalFileContent, err := GetFile(fileName)
	if err != nil {
		return 0, err
	}
	diffMatcher := difflib.NewMatcher([]string{originalFileContent}, []string{fileContent})
	return int((diffMatcher.Ratio() + 0.5) * 100), nil
}

// FileHash returns the sha256sum of the filename
// passed.
func FileHash(fileName string) (string, error) {
	fileContent, err := GetFile(fileName)
	if err != nil {
		return "", err
	}
	return StringHash(fileContent)
}

// StringHash returns the sha256sum of the string
func StringHash(fileContent string) (string, error) {
	hasher := sha256.New()
	if _, err := hasher.Write([]byte(fileContent)); err != nil {
		return "", err
	}
	// Directly encode the byte slice returned by hasher.Sum to avoid
	// corrupting non-UTF8 bytes when converting to and from strings.
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func GetFile(fileName string) (string, error) {
	root, err := os.OpenRoot("./scoredfiles")
	if err != nil {
		return "", fmt.Errorf("failed to open scoredfiles directory: %w", err)
	}
	// nolint:errcheck
	defer root.Close()

	file, err := root.Open(fileName)
	if err != nil {
		return "", err
	}
	// nolint:errcheck
	defer file.Close()

	fileContent, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	return string(fileContent), nil
}

// RunSubchecks abstracts the pattern of checking either a single random subcheck
// or all subchecks (stopping at the first failure).
// An optional debugSuffix (like credentials used) will be appended to the final debug string.
func RunSubchecks[T any](ctx context.Context, items []T, checkAll bool, baseResult Result, debugSuffix string, checkFn func(item T, result Result) Result) Result {
	// helper to generate debug message
	// if msg is "", full message omits msg
	// if msg has contents but suffix is "", full message omits suffix
	// if msg, suffix both have contents, full message is of the format "message (suffix)"
	fullDebugMessage := func(msg, suffix string) string {
		if suffix != "" {
			if msg == "" {
				return suffix
			} else {
				return fmt.Sprintf("%s (%s)", msg, suffix)
			}
		} else {
			return msg
		}
	}

	if len(items) == 0 {
		baseResult.Status = true
		baseResult.Debug = fullDebugMessage(baseResult.Debug, debugSuffix)
		return baseResult
	}

	if checkAll {
		debugParts := []string{}
		for i, item := range items {
			if ctx.Err() != nil {
				result := baseResult
				result.Status = false
				result.Error = "check timeout exceeded"
				result.Debug = fullDebugMessage(fmt.Sprintf("ran out of time after %d of %d checks", i, len(items)), debugSuffix)
				return result
			}
			result := checkFn(item, baseResult)
			if !result.Status {
				result.Debug = fullDebugMessage(result.Debug, debugSuffix)
				return result
			}
			if result.Debug != "" {
				debugParts = append(debugParts, result.Debug)
			}
		}
		baseResult.Status = true

		if len(debugParts) > 0 {
			baseResult.Debug = fmt.Sprintf("all %d checks passed: %s", len(items), strings.Join(debugParts, "; "))
		} else {
			baseResult.Debug = fmt.Sprintf("all %d checks passed", len(items))
		}

		baseResult.Debug = fullDebugMessage(baseResult.Debug, debugSuffix)
		return baseResult
	} else {
		item := items[rand.Intn(len(items))] // #nosec G404 -- non-crypto random selection
		res := checkFn(item, baseResult)
		res.Debug = fullDebugMessage(res.Debug, debugSuffix)
		return res
	}
}

// dialContext dials addr and closes the connection once ctx is done, which
// unblocks any I/O still in flight on it. Use it for protocol libraries that
// don't take a context themselves.
func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { _ = conn.Close() })
	return conn, nil
}

// ctxDialer is a Dial(network, addr) dialer for libraries that take one,
// backed by dialContext.
type ctxDialer struct {
	ctx context.Context
}

func (d ctxDialer) Dial(network, addr string) (net.Conn, error) {
	return dialContext(d.ctx, network, addr)
}
