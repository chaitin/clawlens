package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	gatewayPort = 18789
	dialTimeout = 2 * time.Second
)

// dialFunc abstracts net.DialTimeout for testing.
type dialFunc func(network, address string, timeout time.Duration) (net.Conn, error)

// ScanNetwork checks whether the OpenClaw gateway port is listening.
func ScanNetwork(dial dialFunc) ([]Finding, error) {
	if dial == nil {
		dial = net.DialTimeout
	}
	return scanGatewayPort(dial)
}

func scanGatewayPort(dial dialFunc) ([]Finding, error) {
	var findings []Finding

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	var loopbackOpen bool
	var loopbackAddrs []string
	var virtualIfaceOpen []string
	var virtualIfaceAddrs []string
	var physicalIfaceOpen []string
	var physicalIfaceAddrs []string

	for _, iface := range interfaces {
		// Skip interfaces that are down
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			if ip == nil {
				continue
			}

			// Skip link-local addresses (fe80::/10 for IPv6, 169.254.0.0/16 for IPv4)
			if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}

			// Build address string for connection test
			// IPv6 requires [ip]:port format
			var addrStr string
			if ip.To4() != nil {
				addrStr = fmt.Sprintf("%s:%d", ip.String(), gatewayPort)
			} else {
				addrStr = fmt.Sprintf("[%s]:%d", ip.String(), gatewayPort)
			}

			conn, err := dial("tcp", addrStr, dialTimeout)
			if err != nil {
				continue
			}
			conn.Close()

			// Categorize the interface
			if ip.IsLoopback() {
				loopbackOpen = true
				loopbackAddrs = append(loopbackAddrs, ip.String())
			} else if isVirtualInterface(iface.Name) {
				virtualIfaceOpen = append(virtualIfaceOpen, iface.Name)
				virtualIfaceAddrs = append(virtualIfaceAddrs, ip.String())
			} else {
				physicalIfaceOpen = append(physicalIfaceOpen, iface.Name)
				physicalIfaceAddrs = append(physicalIfaceAddrs, ip.String())
			}
		}
	}

	// Determine severity based on findings
	switch {
	case len(physicalIfaceOpen) > 0:
		// Port open on physical interfaces - likely listening on 0.0.0.0
		findings = append(findings, Finding{
			Category:    CatNetwork,
			Title:       "网关暴露到外部网络",
			Description: fmt.Sprintf("OpenClaw 默认网关端口 %d 在物理网卡上开放，外部网络可访问。", gatewayPort),
			Remediation: "立即将网关绑定地址修改为 127.0.0.1，或通过 iptables/firewalld 限制入站流量。",
			Severity:    Critical,
			Details:     map[string]string{"port": fmt.Sprintf("%d", gatewayPort), "interfaces": fmt.Sprintf("%v", physicalIfaceOpen), "addresses": fmt.Sprintf("%v", physicalIfaceAddrs)},
		})
	case len(virtualIfaceOpen) > 0:
		// Port open only on virtual interface
		findings = append(findings, Finding{
			Category:    CatNetwork,
			Title:       "网关在虚拟网卡上开放",
			Description: fmt.Sprintf("OpenClaw 默认网关端口 %d 仅在虚拟网卡上开放。OpenClaw 可能部署在容器或虚拟机中。", gatewayPort),
			Remediation: "检查虚拟网卡的配置，确保只有受信任的容器或虚拟机可以访问该端口。",
			Severity:    Warning,
			Details:     map[string]string{"port": fmt.Sprintf("%d", gatewayPort), "interfaces": fmt.Sprintf("%v", virtualIfaceOpen), "addresses": fmt.Sprintf("%v", virtualIfaceAddrs)},
		})
	case loopbackOpen:
		// Port open only on loopback
		findings = append(findings, Finding{
			Category:    CatNetwork,
			Title:       "网关端口仅在本地开放",
			Description: fmt.Sprintf("OpenClaw 默认网关端口 %d 绑定到本地回环地址。", gatewayPort),
			Remediation: "确保网关服务已启用访问认证。",
			Severity:    Info,
			Details:     map[string]string{"port": fmt.Sprintf("%d", gatewayPort), "addresses": fmt.Sprintf("%v", loopbackAddrs)},
		})
	}

	return findings, nil
}

// isVirtualInterface checks if the interface name indicates a virtual interface.
// Supports Linux, macOS, and Windows virtual interface naming conventions.
func isVirtualInterface(name string) bool {
	// Common virtual interface prefixes across platforms
	virtualPrefixes := []string{
		// Linux: Docker, Kubernetes, VMs, VPNs
		"docker", "veth", "virbr", "br-", "tun", "tap",
		"cni", "flannel", "calico", "weave", "cilium",
		"kube", "vnet", "vmnet",
		// macOS: VMs, VPNs, system interfaces
		"bridge", "utun", "llw", "awdl", "vnic", "anpi",
		// Windows: Hyper-V, WSL, Loopback
		"vEthernet", "Loopback", "WSL", "vnic", "Hyper-V",
	}

	nameLower := strings.ToLower(name)
	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(nameLower, strings.ToLower(prefix)) {
			return true
		}
	}

	// Additional checks for interface names that contain virtual indicators
	virtualIndicators := []string{
		"virtual", "pseudo", "vmware", "vbox", "parallels",
		"virtualbox", "hyper-v", "hyperv", "wsl",
	}
	for _, indicator := range virtualIndicators {
		if strings.Contains(nameLower, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}
