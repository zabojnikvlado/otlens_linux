// tcp-replay replays a PCAP through the production packet decoder and TCP
// reassembler. It is intended for regression tests and performance profiling.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/tcpreassembly"
)

func main() {
	path := flag.String("pcap", "", "PCAP file to replay")
	flag.Parse()
	if *path == "" {
		log.Fatal("-pcap is required")
	}
	h, err := pcap.OpenOffline(*path)
	if err != nil {
		log.Fatal(err)
	}
	defer h.Close()
	bus := core.NewEventBus()
	e := tcpreassembly.New(bus, tcpreassembly.Config{Enabled: true, ShardCount: 32, GapRecoveryTimeout: 2})
	ch := bus.Subscribe(core.EventTCPStreamData)
	var packets, chunks, bytes uint64
	done := make(chan struct{})
	go func() {
		for ev := range ch {
			c := ev.Data.(core.TCPStreamChunk)
			chunks++
			bytes += uint64(len(c.Data))
		}
		close(done)
	}()
	src := gopacket.NewPacketSource(h, h.LinkType())
	for pkt := range src.Packets() {
		nl := pkt.NetworkLayer()
		tl := pkt.TransportLayer()
		if nl == nil || tl == nil {
			continue
		}
		tcp, ok := tl.(*layers.TCP)
		if !ok {
			continue
		}
		flow := nl.NetworkFlow()
		flags := ""
		if tcp.SYN {
			flags = "SYN"
		}
		if tcp.FIN {
			if flags != "" {
				flags += ","
			}
			flags += "FIN"
		}
		if tcp.RST {
			if flags != "" {
				flags += ","
			}
			flags += "RST"
		}
		e.Push(core.Packet{L4Protocol: "TCP", SrcIP: flow.Src().String(), DstIP: flow.Dst().String(), SrcPort: uint16(tcp.SrcPort), DstPort: uint16(tcp.DstPort), TCPSeq: tcp.Seq, TCPFlags: flags, AppPayload: tcp.Payload, Timestamp: pkt.Metadata().Timestamp})
		packets++
	}
	st := e.Stats()
	fmt.Printf("packets=%d chunks=%d bytes=%d active=%d buffered=%d gaps=%d overlaps=%d retransmitted_bytes=%d\n", packets, chunks, bytes, st.ActiveConnections, st.BufferedBytes, st.GapRecoveries, st.OverlapConflicts, st.RetransmittedBytes)
}
