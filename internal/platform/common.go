package platform

import (
	"fmt"
	"strings"

	"github.com/shirou/gopsutil/v4/process"
)

// FindProcesses returns all OpenClaw-related processes using gopsutil.
func FindProcesses() ([]ProcessInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("listing processes: %w", err)
	}

	var result []ProcessInfo
	for _, proc := range procs {
		name, err := proc.Name()
		if err != nil {
			continue
		}
		cmd, err := proc.Cmdline()
		if err != nil {
			continue
		}
		if !isOpenClawCmdline(cmd) {
			continue
		}
		result = append(result, ProcessInfo{
			PID:  fmt.Sprintf("%d", proc.Pid),
			Name: name,
			Cmd:  cmd,
		})
	}

	return result, nil
}

func isOpenClawCmdline(cmd string) bool {
	cmd = strings.ToLower(cmd)
	if strings.Contains(cmd, "openclaw") && strings.Contains(cmd, "gateway") {
		return true
	}
	return false
}
