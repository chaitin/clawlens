package platform

import (
	"fmt"
	"path/filepath"
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

		if !isOpenClawCommand(name) {
			continue
		}

		cmd, _ := proc.Cmdline()
		result = append(result, ProcessInfo{
			PID:  fmt.Sprintf("%d", proc.Pid),
			Name: name,
			Cmd:  cmd,
		})
	}

	return result, nil
}

func isOpenClawCommand(command string) bool {
	command = strings.ToLower(filepath.Base(command))
	return command == "openclaw" ||
		command == "openclaw-gateway" ||
		command == "openclaw.exe" ||
		command == "openclaw-gateway.exe" ||
		strings.HasPrefix(command, "openclaw-")
}
