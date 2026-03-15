//go:build darwin

package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type darwinPlatform struct{}

func New() Platform {
	return &darwinPlatform{}
}

func (p *darwinPlatform) OpenClawHome() string {
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

func (p *darwinPlatform) FindProcesses() ([]ProcessInfo, error) {
	return FindProcesses()
}

func (p *darwinPlatform) FindServices() ([]ServiceInfo, error) {
	var services []ServiceInfo
	var issue error

	home, _ := os.UserHomeDir()
	plistPaths := []string{
		filepath.Join(home, "Library/LaunchAgents/com.openclaw.gateway.plist"),
		"/Library/LaunchDaemons/com.openclaw.gateway.plist",
	}

	for _, path := range plistPaths {
		if _, err := os.Stat(path); err == nil {
			name := strings.TrimSuffix(filepath.Base(path), ".plist")
			active := false
			if out, err := exec.Command("launchctl", "list").Output(); err == nil {
				active = strings.Contains(string(out), name)
			} else {
				issue = errors.Join(issue, fmt.Errorf("launchctl list: %w", err))
			}
			services = append(services, ServiceInfo{Name: name, Active: active})
		}
	}
	return services, issue
}

func (p *darwinPlatform) OpenBrowser(url string) error {
	return exec.Command("open", url).Start()
}
