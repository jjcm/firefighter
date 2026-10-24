//go:build !linux && !darwin

package host

import (
	"errors"
	"os/exec"
)

func configureProcessGroup(cmd *exec.Cmd) error {
	return errors.New("command execution requires Linux or macOS process-group support")
}

func killProcessGroup(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}
