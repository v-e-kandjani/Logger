package pipeline

import (
	"net"
	"testing"
	"time"
)

func TestPipelineQueueAndIngest(t *testing.T) {
	pipe := NewPipeline(100, 2, "test-node", nil, nil, nil)
	defer pipe.Stop()

	// Ingest packet from Tenant A
	pktA := RawPacket{
		Data:       []byte("<14>Oct 11 22:00:00 server1 sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2"),
		SourceIP:   net.ParseIP("192.168.1.50"),
		SourcePort: 514,
		Protocol:   "udp",
		ReceivedAt: time.Now(),
		Tenant:     "tenant-alpha",
	}

	pipe.Ingest(pktA)
	if pipe.PacketsReceived.Load() != 1 {
		t.Fatalf("expected 1 packet received, got %d", pipe.PacketsReceived.Load())
	}

	// Verify Queue Depth
	if pipe.QueueDepth() < 0 {
		t.Fatalf("unexpected queue depth: %d", pipe.QueueDepth())
	}
}

func TestPipelineStrictFilteringToggle(t *testing.T) {
	pipe := NewPipeline(100, 1, "test-node", nil, nil, nil)
	defer pipe.Stop()

	if pipe.IsStrictFiltering() {
		t.Fatalf("expected strict filtering to be false by default")
	}

	pipe.SetStrictFiltering(true)
	if !pipe.IsStrictFiltering() {
		t.Fatalf("expected strict filtering to be true after toggle")
	}

	pipe.SetStrictFiltering(false)
	if pipe.IsStrictFiltering() {
		t.Fatalf("expected strict filtering to be false after toggle")
	}
}
