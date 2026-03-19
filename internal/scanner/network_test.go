package scanner

import (
	"errors"
	"net"
	"testing"
	"time"
)

type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

func TestScanNetworkPortClosed(t *testing.T) {
	dial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	findings, err := ScanNetwork(dial)
	if err != nil {
		t.Fatalf("ScanNetwork returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when port is closed, got %d", len(findings))
	}
}

func TestScanNetworkPortOpenLocalhost(t *testing.T) {
	dial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		if address == "127.0.0.1:18789" {
			return fakeConn{}, nil
		}
		return nil, errors.New("connection refused")
	}

	findings, err := ScanNetwork(dial)
	if err != nil {
		t.Fatalf("ScanNetwork returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != Info {
		t.Fatalf("expected Info severity, got %v", findings[0].Severity)
	}
	if findings[0].Title != "网关端口仅在本地开放" {
		t.Fatalf("unexpected title: %q", findings[0].Title)
	}
}

func TestScanNetworkPortOpenAllInterfaces(t *testing.T) {
	dial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		return fakeConn{}, nil
	}

	findings, err := ScanNetwork(dial)
	if err != nil {
		t.Fatalf("ScanNetwork returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 findings, got %d", len(findings))
	}
	if findings[0].Severity != Critical {
		t.Fatalf("findings[1]: expected Critical, got %v", findings[1].Severity)
	}
	if findings[0].Title != "网关暴露到外部网络" {
		t.Fatalf("unexpected title: %q", findings[1].Title)
	}
}
