//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type windowsPlatform struct{}

func New() Platform {
	return &windowsPlatform{}
}

func (p *windowsPlatform) OpenClawHome() string {
	// Try to find .openclaw in all user home directories
	homeDirs := findAllUserHomeDirs()
	for _, home := range homeDirs {
		openclawDir := filepath.Join(home, ".openclaw")
		if info, err := os.Stat(openclawDir); err == nil && info.IsDir() {
			return openclawDir
		}
	}
	// Fallback to current user's home directory
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".openclaw")
}

// findAllUserHomeDirs returns all user home directories on Windows.
// It scans the system drive's Users directory.
func findAllUserHomeDirs() []string {
	var homes []string
	seen := make(map[string]bool)

	// Get system drive (usually C:)
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}
	usersDir := filepath.Join(systemDrive, "Users")

	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return homes
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip system/default directories
		if name == "Public" || name == "Default" || name == "Default User" || name == "All Users" ||
			strings.HasPrefix(name, ".") {
			continue
		}
		home := filepath.Join(usersDir, name)
		if !seen[home] {
			seen[home] = true
			homes = append(homes, home)
		}
	}

	return homes
}

func (p *windowsPlatform) FindProcesses() ([]ProcessInfo, error) {
	return FindProcesses()
}

func (p *windowsPlatform) FindServices() ([]ServiceInfo, error) {
	var services []ServiceInfo

	serviceNames := []string{"OpenClaw", "OpenClawGateway"}
	for _, name := range serviceNames {
		out, err := exec.Command("sc", "query", name).Output()
		if err != nil {
			continue
		}
		output := string(out)
		if strings.Contains(output, name) {
			active := strings.Contains(output, "RUNNING")
			services = append(services, ServiceInfo{Name: name, Active: active})
		}
	}
	return services, nil
}

func (p *windowsPlatform) OpenBrowser(url string) error {
	return exec.Command("cmd", "/c", "start", url).Start()
}
