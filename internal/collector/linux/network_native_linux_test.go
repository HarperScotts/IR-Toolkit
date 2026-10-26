package linux

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ir-toolkit/internal/analyzer"
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	localstore "ir-toolkit/internal/store/local"
)

func TestNativeNetworkCollectorOwnLoopback(t *testing.T) {
	for _, test := range []struct{ family, address string }{{"4", "127.0.0.1:0"}, {"6", "[::1]:0"}} {
		t.Run("IPv"+test.family, func(t *testing.T) {
			listener, err := net.Listen("tcp"+test.family, test.address)
			if err != nil {
				if test.family == "6" {
					t.Skip("IPv6 unavailable", err)
				}
				t.Fatal(err)
			}
			defer listener.Close()
			packet, err := net.ListenPacket("udp"+test.family, test.address)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			snapshot, err := collectNetwork(ctx, "/proc")
			if err != nil {
				t.Log("Other observations incomplete:", err)
			}
			tcpPort := uint32(listener.Addr().(*net.TCPAddr).Port)
			udpPort := uint32(packet.LocalAddr().(*net.UDPAddr).Port)
			tcpFound, udpFound := false, false
			for _, connection := range snapshot.Connections {
				if connection.PID != uint32(os.Getpid()) || connection.ProcessInstanceID == "" {
					continue
				}
				if connection.Protocol == "TCP" && connection.LocalPort == tcpPort && connection.State == "LISTEN" {
					tcpFound = true
				}
				if connection.Protocol == "UDP" && connection.LocalPort == udpPort {
					udpFound = true
				}
			}
			process, err := readProcess(uint32(os.Getpid()))
			if err != nil || process.ProcessInstanceID == "" {
				t.Fatal("native process identity", err)
			}
			analysis := analyzer.NewProcessNetworkAnalyzer().Analyze(ctx, []model.Process{process}, snapshot.Connections)
			caseDir := t.TempDir()
			if err := analyzer.WriteNetworkAnalysis(filepath.Join(caseDir, "analysis", "network_analysis.json"), analysis); err != nil {
				t.Fatal(err)
			}
			query, err := localstore.New(caseDir).QueryNetwork(store.NetworkQueryOptions{PID: process.PID})
			if err != nil {
				t.Fatal(err)
			}
			tcpStored, udpStored := false, false
			for _, item := range query.Items {
				wantID := fmt.Sprintf("network:%d:%s:%s:%d:%s:%d:%s", item.PID, item.Protocol, item.LocalAddress, item.LocalPort, item.RemoteAddress, item.RemotePort, item.Kind)
				if item.ID != wantID || item.External {
					t.Fatalf("canonical ID or Analyzer membership changed: %+v", item)
				}
				if item.LocalPort == tcpPort && item.Protocol == "TCP" {
					tcpStored = true
				}
				if item.LocalPort == udpPort && item.Protocol == "UDP" {
					udpStored = true
				}
			}
			if !tcpStored || !udpStored {
				t.Fatal("Linux sockets did not reach Store queries")
			}
			if !tcpFound || !udpFound {
				t.Fatalf("own loopback socket lost: tcp=%v udp=%v snapshot=%+v", tcpFound, udpFound, snapshot)
			}
			for _, connection := range snapshot.Connections {
				if connection.PID == process.PID && connection.ProcessInstanceID != process.ProcessInstanceID {
					t.Fatal("process/network instance mismatch")
				}
			}
		})
	}
}
