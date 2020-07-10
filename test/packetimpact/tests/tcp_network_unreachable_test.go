// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp_synsent_reset_test

import (
	"context"
	"flag"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	tb.RegisterFlags(flag.CommandLine)
}

// TestTCPSynSentUnreachable verifies that TCP connections fail immediately when
// an ICMP destination unreachable message is sent in response to the inital
// SYN.
func TestTCPSynSentUnreachable(t *testing.T) {
	// Create the DUT and connection.
	dut := tb.NewDUT(t)
	defer dut.TearDown()
	clientFD, clientPort := dut.CreateBoundSocket(unix.SOCK_STREAM, unix.IPPROTO_TCP, net.ParseIP(tb.RemoteIPv4))
	port := uint16(9001)
	conn := tb.NewTCPIPv4(t, tb.TCP{SrcPort: &port, DstPort: &clientPort}, tb.TCP{SrcPort: &clientPort, DstPort: &port})
	defer conn.Close()

	// Bring the DUT to SYN-SENT state with a blocking connect. ConnectWithErrno
	// should fail upon delivery of the ICMP packet.
	errCh := make(chan error)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), tb.RPCTimeout)
		defer cancel()
		sa := unix.SockaddrInet4{Port: int(port)}
		copy(sa.Addr[:], net.IP(net.ParseIP(tb.LocalIPv4)).To4())
		_, err := dut.ConnectWithErrno(ctx, clientFD, &sa)
		errCh <- err
	}()

	// Get the SYN.
	tcpLayers, err := conn.ExpectData(&tb.TCP{Flags: tb.Uint8(header.TCPFlagSyn)}, nil, time.Second)
	if err != nil {
		t.Fatalf("expected SYN\n")
	}

	// Send a host unreachable message.
	rawConn := (*tb.Connection)(&conn)
	layers := rawConn.CreateFrame(nil)
	layers = layers[:len(layers)-1]
	const ipLayer = 1
	const tcpLayer = ipLayer + 1
	ip, ok := tcpLayers[ipLayer].(*tb.IPv4)
	if !ok {
		t.Fatalf("expected %s to be IPv4", tcpLayers[ipLayer])
	}
	tcp, ok := tcpLayers[tcpLayer].(*tb.TCP)
	if !ok {
		t.Fatalf("expected %s to be TCP", tcpLayers[tcpLayer])
	}
	var icmpv4 tb.ICMPv4 = tb.ICMPv4{Type: tb.ICMPv4Type(header.ICMPv4DstUnreachable), Code: tb.Uint8(header.ICMPv4HostUnreachable)}
	layers = append(layers, &icmpv4, ip, tcp)
	rawConn.SendFrameStateless(layers)

	// Connect should return that the host is unreachable.
	if err := <-errCh; err != syscall.Errno(unix.EHOSTUNREACH) {
		t.Fatalf("expected connect to fail with EHOSTUNREACH, but got %v", err)
	}
}
