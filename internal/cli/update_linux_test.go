package cli

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestUpdateWithoutTerminal(t *testing.T) {
	if os.Getenv("XCERTM_TEST_NO_TTY") == "1" {
		confirmed, err := confirmInteractiveUpdate()
		if confirmed || err == nil || !strings.Contains(err.Error(), "--yes") {
			t.Fatalf("missing terminal did not require explicit authorization: %v, %v", confirmed, err)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestUpdateWithoutTerminal$")
	command.Env = append(os.Environ(), "XCERTM_TEST_NO_TTY=1")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("terminal-free subprocess failed: %v\n%s", err, output)
	}
}
