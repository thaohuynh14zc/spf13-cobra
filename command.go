package cobra

import (
	"context"
	"fmt"
	"os"
)

type Command struct {
	ctx context.Context
	// ... other fields ...
}

func (c *Command) ExecuteContext(ctx context.Context) error {
	c.ctx = ctx
	return c.Execute()
}

func (c *Command) Execute() error {
	return c.execute(os.Args[1:])
}

func (c *Command) execute(a []string) (cmd *Command, err error) {
	if c == nil {
		return nil, fmt.Errorf("Called Execute() on a nil Command")
	}

	if c.ctx == nil {
		c.ctx = context.Background()
	}

	// Find the command
	cmd, flags, err := c.Find(a)
	if err != nil {
		return nil, err
	}

	if cmd.ctx == nil {
		cmd.ctx = c.ctx
	}

	// ... rest of execution ...
	return cmd, nil
}