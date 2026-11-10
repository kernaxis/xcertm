// Package cli handles command-line arguments and output, without lifecycle logic.
package cli

import (
	"context"
	"fmt"
	"io"

	urfavecli "github.com/urfave/cli/v3"
)

// Run executes the CLI and returns 0 on success or 1 on error.
// args includes the executable name, as in os.Args.
func Run(ctx context.Context, args []string, version string, stdout, stderr io.Writer) int {
	command := &urfavecli.Command{
		Name:      "xcertm",
		Usage:     "Manage the lifecycle of TLS certificates (early development)",
		Version:   version,
		Writer:    stdout,
		ErrWriter: stderr,
		Flags:     rootFlags(),
		// Keep process exits and diagnostics here, without changing library globals.
		ExitErrHandler: func(context.Context, *urfavecli.Command, error) {},
		OnUsageError: func(_ context.Context, _ *urfavecli.Command, err error, _ bool) error {
			return err
		},
		Action: func(_ context.Context, cmd *urfavecli.Command) error {
			if cmd.Args().Present() {
				return fmt.Errorf("unknown command %q", cmd.Args().First())
			}
			return urfavecli.ShowRootCommandHelp(cmd)
		},
		Commands: []*urfavecli.Command{
			{
				Name:  "version",
				Usage: "Print the version",
				Action: func(_ context.Context, cmd *urfavecli.Command) error {
					if cmd.Args().Present() {
						return fmt.Errorf("version does not accept arguments")
					}
					_, err := fmt.Fprintf(cmd.Root().Writer, "xcertm version %s\n", version)
					return err
				},
			},
		},
	}
	command.Commands = append(command.Commands, lifecycleCommands()...)

	if err := command.Run(ctx, args); err != nil {
		fmt.Fprintf(stderr, "xcertm: %v\n", err)
		return 1
	}
	return 0
}
