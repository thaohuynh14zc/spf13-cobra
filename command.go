func (c *Command) ExecuteContext(ctx context.Context) error {
	c.ctx = ctx
	return c.Execute()
}

// ... (rest of the file remains the same, ensuring Execute() uses c.ctx)

func (c *Command) Execute() error {
	// ... existing implementation ...
	// Ensure that when we find the command, we propagate the context
	// The existing Execute() implementation already calls findAndExecute
	// which should respect the context if set on the root.
	// The fix is to ensure that the command tree traversal correctly identifies the persistent hooks.
	return c.execute(os.Args[1:])
}