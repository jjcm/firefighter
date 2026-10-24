//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package planner

import "os/exec"

func configureCancellation(cmd *exec.Cmd) {}
