package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kernaxis/xcertm/internal/update"
	urfavecli "github.com/urfave/cli/v3"
)

func updateCommand(version string) *urfavecli.Command {
	return &urfavecli.Command{
		Name:  "update",
		Usage: "Install the latest stable release after confirmation",
		Flags: []urfavecli.Flag{
			&urfavecli.BoolFlag{Name: "check", Usage: "Check for an update without installing"},
			&urfavecli.BoolFlag{Name: "yes", Usage: "Confirm installation without prompting"},
		},
		Action: func(ctx context.Context, cmd *urfavecli.Command) error {
			if cmd.Args().Present() {
				return fmt.Errorf("update does not accept arguments")
			}
			if cmd.Bool("check") && cmd.Bool("yes") {
				return fmt.Errorf("--check and --yes are mutually exclusive")
			}
			client := update.NewClient()
			release, err := client.Latest(ctx)
			if err != nil {
				return err
			}
			out := cmd.Root().Writer
			proceed, err := reportUpdate(out, version, release.Version, cmd.Bool("check"))
			if err != nil || !proceed {
				return err
			}
			path, err := update.Executable()
			if err != nil {
				return fmt.Errorf("cannot locate running binary: %w", err)
			}
			if _, err := fmt.Fprintf(out, "This will install xcertm %s over %s.\nBinary: %s\n", release.Version, version, path); err != nil {
				return err
			}
			if !cmd.Bool("yes") {
				confirmed, err := confirmInteractiveUpdate()
				if err != nil {
					return err
				}
				if !confirmed {
					_, err := fmt.Fprintln(out, "Update cancelled.")
					return err
				}
			}
			ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			if err := client.Install(ctx, release, path); err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "Installed xcertm %s.\n", release.Version)
			return err
		},
	}
}

func reportUpdate(out io.Writer, current, target string, check bool) (proceed bool, err error) {
	comparison, known := update.Compare(current, target)
	if known && comparison >= 0 {
		if comparison == 0 {
			_, err = fmt.Fprintf(out, "You are up to date (%s).\n", current)
		} else {
			_, err = fmt.Fprintf(out, "Installed version %s is newer than the latest stable release %s; no downgrade performed.\n", current, target)
		}
		return false, err
	}
	if !known {
		if _, err := fmt.Fprintf(out, "Installed version %q is a development or unrecognized build.\n", current); err != nil {
			return false, err
		}
	}
	if check {
		_, err := fmt.Fprintf(out, "Latest stable release: %s (installed: %s).\n", target, current)
		return false, err
	}
	return true, nil
}

func confirmInteractiveUpdate() (bool, error) {
	// /dev/tty avoids consuming piped input and works when stdin is redirected.
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, fmt.Errorf("interactive confirmation requires a terminal; use --yes to explicitly authorize installation")
	}
	defer tty.Close()
	return confirmUpdate(tty, tty)
}

func confirmUpdate(input io.Reader, output io.Writer) (bool, error) {
	if _, err := fmt.Fprint(output, "Continue? [y/N] "); err != nil {
		return false, err
	}
	line, err := bufio.NewReader(io.LimitReader(input, 1024)).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}
