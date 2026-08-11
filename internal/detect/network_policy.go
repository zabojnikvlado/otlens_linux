package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

var remoteManagementPorts = map[uint16]string{
	22: "ssh", 23: "telnet", 135: "rpc", 139: "netbios", 445: "smb",
	3389: "rdp", 5900: "vnc", 5901: "vnc", 5902: "vnc", 5985: "winrm", 5986: "winrm-tls",
}

var otServicePorts = map[uint16]string{
	102: "s7", 502: "modbus", 20000: "dnp3", 2404: "iec104", 4840: "opcua",
	44818: "ethernetip", 47808: "bacnet",
}

func (e *Engine) startBuiltinNetworkPolicyWatch(bus *core.EventBus) {
	ch := bus.Subscribe(core.EventPacketParsed)
	go func() {
		for event := range ch {
			p, ok := event.Data.(core.Packet)
			if !ok || p.SrcIP == "" || p.DstIP == "" || p.FromAnalysis {
				continue
			}
			e.handleBuiltinNetworkPolicy(p)
		}
	}()
}

func (e *Engine) handleBuiltinNetworkPolicy(p core.Packet) {
	now := p.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	// A reporting-loss rule is only meaningful while capture itself is seeing
	// traffic. This heartbeat prevents a stopped capture/interface from being
	// misreported as dozens of controller telemetry losses.
	e.policyMutex.Lock()
	e.lastPacketObserved = now
	e.policyMutex.Unlock()

	service, isRemote := remoteManagementPorts[p.DstPort]
	otProto, isOT := otServicePorts[p.DstPort]

	// Only treat a TCP connection as newly initiated on a SYN without ACK.
	// UDP has no handshake, so the first/recurring datagram is the signal.
	initiated := p.L4Protocol != "TCP" || (strings.Contains(p.TCPFlags, "SYN") && !strings.Contains(p.TCPFlags, "ACK"))

	if isRemote && initiated {
		trusted := e.isTrustedRemoteManagement(p.SrcIP, p.DstIP, p.DstPort)
		learning := e.behaviorDetectionsSuppressed()
		if learning && !e.sourceRoleIsExplicitlyUntrusted(p.SrcIP) {
			e.learnRemoteManagement(p.SrcIP, p.DstIP, p.DstPort)
			trusted = true
		} else if !learning && !trusted {
			srcCtx, _ := e.assetContext(p.SrcIP)
			dstCtx, _ := e.assetContext(p.DstIP)
			evidence := map[string]interface{}{
				"source_ip": p.SrcIP, "destination_ip": p.DstIP, "destination_port": p.DstPort,
				"service": service, "source_role": srcCtx.Role, "destination_role": dstCtx.Role,
				"source_zone": srcCtx.Zone, "destination_zone": dstCtx.Zone,
			}
			e.raiseBuiltinAlert("builtin.first_seen_remote_management", AlertFirstSeenRemoteManagement, "medium",
				fmt.Sprintf("remote-first|%s|%s|%d", p.SrcIP, p.DstIP, p.DstPort),
				fmt.Sprintf("First-seen %s remote-management relationship %s -> %s", service, p.SrcIP, p.DstIP),
				p.SrcIP, evidence, now, 30*time.Minute)
		}

		if e.isOTAsset(p.DstIP) && !trusted {
			e.excludePacketFromLearning(p, "unapproved remote management into OT")
			srcCtx, _ := e.assetContext(p.SrcIP)
			dstCtx, _ := e.assetContext(p.DstIP)
			evidence := map[string]interface{}{
				"source_ip": p.SrcIP, "destination_ip": p.DstIP, "destination_port": p.DstPort,
				"service": service, "source_role": srcCtx.Role, "destination_role": dstCtx.Role,
				"source_zone": srcCtx.Zone, "destination_zone": dstCtx.Zone,
			}
			e.raiseBuiltinAlert("builtin.remote_management_into_ot", AlertRemoteAdminIntoOT, "high",
				fmt.Sprintf("remote-ot|%s|%s|%d", p.SrcIP, p.DstIP, p.DstPort),
				fmt.Sprintf("Unapproved %s remote-management access %s -> OT asset %s", service, p.SrcIP, p.DstIP),
				p.SrcIP, evidence, now, alertEpisodeGap)
			if p.DstPort == 445 || p.DstPort == 139 {
				e.raiseBuiltinAlert("builtin.smb_into_ot", AlertSMBIntoOT, "medium",
					fmt.Sprintf("smb-ot|%s|%s", p.SrcIP, p.DstIP),
					fmt.Sprintf("SMB traffic from %s entered OT asset %s", p.SrcIP, p.DstIP),
					p.SrcIP, evidence, now, alertEpisodeGap)
			}
		}
	}

	if !isOT {
		return
	}
	// Port-level OT access catches reads/discovery as well as commands. The
	// protocol-aware ICS handler separately raises command/write-specific rules.
	e.markOTAsset(p.DstIP)
	trustedAccess := e.isTrustedOTAccess(p.SrcIP, p.DstIP)
	if e.behaviorDetectionsSuppressed() {
		if !e.sourceRoleIsExplicitlyUntrusted(p.SrcIP) {
			// Port visibility establishes that this source may access the OT
			// service, but it does not grant write/operate authority. The decoded
			// ICS policy path learns command authority only from actual commands.
			e.learnOTAccess(p.SrcIP, p.DstIP)
			e.learnOTProtocolForRelation(p.SrcIP, p.DstIP, otProto, p.DstPort)
			trustedAccess = true
		}
	} else if initiated && !trustedAccess {
		srcCtx, _ := e.assetContext(p.SrcIP)
		dstCtx, _ := e.assetContext(p.DstIP)
		evidence := map[string]interface{}{
			"source_ip": p.SrcIP, "destination_ip": p.DstIP, "destination_port": p.DstPort,
			"ot_protocol": otProto, "source_role": srcCtx.Role, "destination_role": dstCtx.Role,
			"source_zone": srcCtx.Zone, "destination_zone": dstCtx.Zone,
		}
		e.raiseBuiltinAlert("builtin.direct_ot_protocol_access", AlertDirectOTProtocolAccess, "high",
			fmt.Sprintf("direct-ot|%s|%s|%s", p.SrcIP, p.DstIP, otProto),
			fmt.Sprintf("%s directly accessed %s on OT asset %s without a learned/approved relationship", p.SrcIP, otProto, p.DstIP),
			p.SrcIP, evidence, now, alertEpisodeGap)
	}

	// Large transfer detector uses wire bytes and is deliberately independent
	// of payload decoding, so a download can still be detected if the protocol
	// parser cannot fully decode a vendor-specific programming sequence.
	if p.Length > 0 {
		transferWindow := time.Duration(e.builtinParameter("builtin.large_controller_transfer", "window_seconds", 300)) * time.Second
		if transferWindow <= 0 {
			transferWindow = 5 * time.Minute
		}
		transferThreshold := uint64(e.builtinParameter("builtin.large_controller_transfer", "bytes_threshold", 10*1024*1024))
		if transferThreshold == 0 {
			transferThreshold = 10 * 1024 * 1024
		}
		key := relationKey(p.SrcIP, p.DstIP, p.DstPort)
		e.policyMutex.Lock()
		w := e.remoteTransfers[key]
		if w == nil || now.Sub(w.FirstSeen) > transferWindow {
			w = &packetWindow{FirstSeen: now}
			e.remoteTransfers[key] = w
		}
		w.LastSeen = now
		w.Bytes += uint64(p.Length)
		bytes := w.Bytes
		e.policyMutex.Unlock()
		if bytes >= transferThreshold {
			evidence := map[string]interface{}{"source_ip": p.SrcIP, "destination_ip": p.DstIP, "destination_port": p.DstPort, "ot_protocol": otProto, "bytes_in_window": bytes, "window_seconds": transferWindow.Seconds(), "bytes_threshold": transferThreshold}
			e.raiseBuiltinAlert("builtin.large_controller_transfer", AlertLargeControllerTransfer, "high",
				"controller-transfer|"+key,
				fmt.Sprintf("Large transfer toward controller %s over %s: %d bytes within %s", p.DstIP, otProto, bytes, transferWindow),
				p.SrcIP, evidence, now, 30*time.Minute)
		}
	}
}
