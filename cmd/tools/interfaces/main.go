// Command interfaces is a small diagnostic tool: it lists every
// capture-capable network device pcap/Npcap can see, printing each
// device's raw name (what capture.Engine actually needs) alongside
// its human-readable description (what config.yaml's
// capture.interface is usually set to). Run this whenever
// otlens fails to start with "capture interface not found" — the
// error message itself now prints the same list, but this tool is
// useful for checking available devices before even touching
// config.yaml.
//
// Usage: go run ./cmd/tools/interfaces
package main

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

func main() {

	devices, _ := pcap.FindAllDevs()

	for _, d := range devices {

		// Name is the raw pcap device (e.g. \Device\NPF_{GUID} on
		// Windows) — this is what capture.interface in config.yaml
		// ultimately resolves to.
		fmt.Println(d.Name)

		// Description is the adapter's hardware description (e.g.
		// "Intel(R) Ethernet Connection I219-V") — NOT the same as
		// the friendly connection name shown in Windows' Network
		// Connections panel (e.g. "Ethernet"); see
		// capture.ResolveDevice's doc comment for why that matters.
		fmt.Println(d.Description)

	}

}
