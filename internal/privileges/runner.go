package privileges

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

type ExecRunner struct{}
type boundedOutput struct{ b bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.b.Len()+len(p) > 1<<20 {
		return 0, errors.New("output limit")
	}
	return b.b.Write(p)
}
func (ExecRunner) Run(ctx context.Context, command string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, command, args...)
	c.WaitDelay = time.Second
	var output boundedOutput
	c.Stdout = &output
	c.Stderr = io.Discard
	if err := c.Run(); err != nil {
		return nil, errors.New("fixed policy control failed")
	}
	return output.b.Bytes(), nil
}
