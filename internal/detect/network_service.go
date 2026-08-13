package detect

import (
	"net"
	"strings"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

const dynamicPortFloor uint16 = 49152

var commonTCPServices = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	88: "kerberos", 102: "s7", 110: "pop3", 111: "rpcbind", 135: "rpc", 139: "netbios",
	143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 502: "modbus",
	515: "lpd", 587: "smtp-submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
	1433: "mssql", 1521: "oracle", 1883: "mqtt", 2404: "iec104", 3306: "mysql", 3389: "rdp",
	4840: "opcua", 5432: "postgresql", 5672: "amqp", 5900: "vnc", 5985: "winrm",
	5986: "winrm-tls", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 8883: "mqtt-tls",
	20000: "dnp3", 44818: "ethernetip",
}

var commonUDPServices = map[uint16]string{
	53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp", 88: "kerberos", 123: "ntp",
	137: "netbios-ns", 138: "netbios-dgm", 161: "snmp", 162: "snmp-trap", 500: "ike",
	514: "syslog", 520: "rip", 623: "ipmi", 1194: "openvpn", 1701: "l2tp", 1812: "radius",
	1813: "radius-accounting", 1900: "ssdp", 3702: "ws-discovery", 4500: "ipsec-nat-t",
	4789: "vxlan", 5353: "mdns", 5355: "llmnr", 5683: "coap", 6343: "sflow",
	8472: "vxlan-linux", 20000: "dnp3", 44818: "ethernetip", 47808: "bacnet",
}

var routineDiscoveryUDPPorts = map[uint16]struct{}{
	67: {}, 68: {}, 137: {}, 138: {}, 1900: {}, 3702: {}, 5353: {}, 5355: {}, 546: {}, 547: {},
}

func serviceNameForPort(protocol string, port uint16) string {
	if port == 0 {
		return "dynamic"
	}
	if strings.EqualFold(protocol, "tcp") {
		if name := commonTCPServices[port]; name != "" {
			return name
		}
	}
	if strings.EqualFold(protocol, "udp") {
		if name := commonUDPServices[port]; name != "" {
			return name
		}
	}
	return ""
}

func knownServicePort(protocol string, port uint16) bool {
	return serviceNameForPort(protocol, port) != ""
}

// baselineServicePort chooses the stable service side of a communication
// relationship without treating a changing client port as a new service.
// TCP handshake direction wins; known protocol ports win next; then the
// IANA dynamic/private range separates the likely client side. Unknown
// high/high UDP pairs collapse to port 0 ("dynamic UDP") rather than creating
// one baseline finding per random peer port.
func baselineServicePort(packet core.Packet) uint16 {
	src, dst := packet.SrcPort, packet.DstPort
	if src == 0 {
		return dst
	}
	if dst == 0 {
		return src
	}
	if src == dst {
		return src
	}
	if strings.EqualFold(packet.L4Protocol, "tcp") {
		flags := strings.ToUpper(packet.TCPFlags)
		if strings.Contains(flags, "SYN") {
			if strings.Contains(flags, "ACK") {
				return src
			}
			return dst
		}
	}
	srcKnown, dstKnown := knownServicePort(packet.L4Protocol, src), knownServicePort(packet.L4Protocol, dst)
	if srcKnown != dstKnown {
		if srcKnown {
			return src
		}
		return dst
	}
	if src >= dynamicPortFloor && dst < dynamicPortFloor {
		return dst
	}
	if dst >= dynamicPortFloor && src < dynamicPortFloor {
		return src
	}
	if strings.EqualFold(packet.L4Protocol, "udp") && src >= dynamicPortFloor && dst >= dynamicPortFloor {
		return 0
	}
	if src < dst {
		return src
	}
	return dst
}

// legacyBaselineServicePort preserves the pre-v22 key heuristic so a deployed
// sensor does not forget an already learned/approved communication pattern on
// upgrade. New observations use baselineServicePort, but old trusted keys are
// still recognized until normal baseline reset/relearning.
func legacyBaselineServicePort(packet core.Packet) uint16 {
	service := packet.SrcPort
	flags := strings.ToUpper(packet.TCPFlags)
	if strings.EqualFold(packet.L4Protocol, "tcp") && strings.Contains(flags, "SYN") {
		if strings.Contains(flags, "ACK") && packet.SrcPort != 0 {
			service = packet.SrcPort
		} else if !strings.Contains(flags, "ACK") && packet.DstPort != 0 {
			service = packet.DstPort
		} else if packet.DstPort < service {
			service = packet.DstPort
		}
	} else if packet.DstPort < service {
		service = packet.DstPort
	}
	return service
}

func groupDestination(packet core.Packet) bool {
	if ip := net.ParseIP(strings.TrimSpace(packet.DstIP)); ip != nil && ip.IsMulticast() {
		return true
	}
	if packet.DstIP == "255.255.255.255" {
		return true
	}
	hw, err := net.ParseMAC(strings.TrimSpace(packet.DstMAC))
	return err == nil && len(hw) > 0 && hw[0]&0x01 != 0
}

func routineDiscoveryTraffic(packet core.Packet) bool {
	if !strings.EqualFold(packet.L4Protocol, "udp") || !groupDestination(packet) {
		return false
	}
	_, srcOK := routineDiscoveryUDPPorts[packet.SrcPort]
	_, dstOK := routineDiscoveryUDPPorts[packet.DstPort]
	return srcOK || dstOK
}
