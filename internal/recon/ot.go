package recon

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/management"
)

// probeOTIdentity performs only bounded, read-only identity discovery against a
// single explicitly authorised target. It never writes process values or changes
// controller state.
func probeOTIdentity(ctx context.Context, target string, protocols []string, timeout time.Duration) []management.ReconEvidence {
	var out []management.ReconEvidence
	for _, proto := range protocols {
		switch strings.ToLower(strings.TrimSpace(proto)) {
		case "modbus", "modbus-tcp":
			if values, err := modbusDeviceID(ctx, target, timeout); err == nil {
				for k, v := range values {
					out = append(out, evidence("ot."+k, v, "modbus_device_identification", 92))
				}
			}
		case "ethernet-ip", "enip", "cip":
			if values, err := enipListIdentity(ctx, target, timeout); err == nil {
				for k, v := range values {
					out = append(out, evidence("ot."+k, v, "ethernet_ip_list_identity", 95))
				}
			}
		case "s7", "s7comm":
			if values, err := s7Identity(ctx, target, timeout); err == nil {
				for k, v := range values {
					out = append(out, evidence("ot."+k, v, "s7_cotp_identity", 72))
				}
			}
		case "opcua", "opc-ua":
			if values, err := opcUAHello(ctx, target, timeout); err == nil {
				for k, v := range values {
					out = append(out, evidence("ot."+k, v, "opcua_hello_ack", 75))
				}
			}
		case "bacnet":
			if values, err := bacnetWhoIs(ctx, target, timeout); err == nil {
				for k, v := range values {
					out = append(out, evidence("ot."+k, v, "bacnet_who_is", 88))
				}
			}
		}
	}
	return out
}

func dialTCP(ctx context.Context, host string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err == nil {
		_ = c.SetDeadline(time.Now().Add(timeout))
	}
	return c, err
}

func modbusDeviceID(ctx context.Context, host string, timeout time.Duration) (map[string]string, error) {
	c, err := dialTCP(ctx, host, 502, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	// MBAP + Read Device Identification (FC 43 / MEI 14), basic stream.
	req := []byte{0, 1, 0, 0, 0, 5, 1, 0x2b, 0x0e, 1, 0}
	if _, err = c.Write(req); err != nil {
		return nil, err
	}
	b := make([]byte, 2048)
	n, err := c.Read(b)
	if err != nil || n < 15 {
		return nil, fmt.Errorf("invalid modbus identity response")
	}
	b = b[:n]
	if b[7] != 0x2b || b[8] != 0x0e {
		return nil, fmt.Errorf("unexpected modbus response")
	}
	count := int(b[13])
	pos := 14
	names := map[byte]string{0: "vendor", 1: "product", 2: "firmware", 3: "vendor_url", 4: "product_name", 5: "model", 6: "application"}
	out := map[string]string{}
	for i := 0; i < count && pos+2 <= len(b); i++ {
		id, l := b[pos], int(b[pos+1])
		pos += 2
		if pos+l > len(b) {
			break
		}
		v := strings.TrimSpace(string(b[pos : pos+l]))
		pos += l
		if v != "" {
			k := names[id]
			if k == "" {
				k = fmt.Sprintf("object_%d", id)
			}
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty modbus identity")
	}
	out["protocol"] = "Modbus/TCP"
	return out, nil
}

func enipListIdentity(ctx context.Context, host string, timeout time.Duration) (map[string]string, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, "44818"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	req := make([]byte, 24)
	binary.LittleEndian.PutUint16(req[0:2], 0x0063)
	if _, err = c.Write(req); err != nil {
		return nil, err
	}
	b := make([]byte, 1500)
	n, err := c.Read(b)
	if err != nil || n < 44 {
		return nil, fmt.Errorf("invalid list identity response")
	}
	b = b[:n]
	if binary.LittleEndian.Uint16(b[0:2]) != 0x0063 {
		return nil, fmt.Errorf("unexpected encapsulation command")
	}
	// First identity item: vendor/device/product/revision/status/serial/name/state.
	pos := 24
	if pos+2 > len(b) {
		return nil, fmt.Errorf("truncated")
	}
	count := int(binary.LittleEndian.Uint16(b[pos:]))
	pos += 2
	if count < 1 || pos+4 > len(b) {
		return nil, fmt.Errorf("no identity item")
	}
	pos += 4
	if pos+20 > len(b) {
		return nil, fmt.Errorf("truncated identity")
	}
	pos += 16
	vendor := binary.LittleEndian.Uint16(b[pos:])
	device := binary.LittleEndian.Uint16(b[pos+2:])
	product := binary.LittleEndian.Uint16(b[pos+4:])
	major, minor := b[pos+6], b[pos+7]
	serial := binary.LittleEndian.Uint32(b[pos+10:])
	nameLen := int(b[pos+14])
	pos += 15
	name := ""
	if pos+nameLen <= len(b) {
		name = strings.TrimSpace(string(b[pos : pos+nameLen]))
	}
	return map[string]string{"protocol": "EtherNet/IP", "vendor_id": fmt.Sprint(vendor), "device_type": fmt.Sprint(device), "product_code": fmt.Sprint(product), "firmware": fmt.Sprintf("%d.%d", major, minor), "serial": fmt.Sprintf("%08X", serial), "product_name": name}, nil
}

func s7Identity(ctx context.Context, host string, timeout time.Duration) (map[string]string, error) {
	c, err := dialTCP(ctx, host, 102, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	// ISO-on-TCP COTP connection request. No PLC state or process data access.
	req := []byte{3, 0, 0, 22, 17, 0xe0, 0, 0, 0, 1, 0, 0xc1, 2, 1, 0, 0xc2, 2, 1, 2, 0xc0, 1, 10}
	if _, err = c.Write(req); err != nil {
		return nil, err
	}
	b := make([]byte, 256)
	n, err := c.Read(b)
	if err != nil || n < 7 || b[0] != 3 || b[5] != 0xd0 {
		return nil, fmt.Errorf("no valid COTP confirm")
	}
	return map[string]string{"protocol": "S7comm/ISO-on-TCP", "vendor": "Siemens", "endpoint": "COTP TSAP accepted"}, nil
}

func opcUAHello(ctx context.Context, host string, timeout time.Duration) (map[string]string, error) {
	c, err := dialTCP(ctx, host, 4840, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	endpoint := "opc.tcp://" + host + ":4840"
	size := 32 + len(endpoint)
	b := make([]byte, size)
	copy(b, "HELF")
	binary.LittleEndian.PutUint32(b[4:8], uint32(size))
	binary.LittleEndian.PutUint32(b[8:12], 0)
	binary.LittleEndian.PutUint32(b[12:16], 65535)
	binary.LittleEndian.PutUint32(b[16:20], 65535)
	binary.LittleEndian.PutUint32(b[20:24], 0)
	binary.LittleEndian.PutUint32(b[24:28], 0)
	binary.LittleEndian.PutUint32(b[28:32], uint32(len(endpoint)))
	copy(b[32:], endpoint)
	if _, err = c.Write(b); err != nil {
		return nil, err
	}
	r := make([]byte, 256)
	n, err := c.Read(r)
	if err != nil || n < 8 || string(r[:3]) != "ACK" {
		return nil, fmt.Errorf("no OPC UA ACK")
	}
	return map[string]string{"protocol": "OPC UA", "endpoint": endpoint, "transport": "opc.tcp"}, nil
}

func bacnetWhoIs(ctx context.Context, host string, timeout time.Duration) (map[string]string, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, "47808"))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	req := []byte{0x81, 0x0a, 0, 8, 1, 0x20, 0xff, 0xff}
	if _, err = c.Write(req); err != nil {
		return nil, err
	}
	b := make([]byte, 512)
	n, err := c.Read(b)
	if err != nil || n < 12 {
		return nil, fmt.Errorf("no BACnet I-Am")
	}
	// Find unconfirmed I-Am service choice 0. The object id and vendor are fixed-width in normal replies.
	for i := 0; i+10 <= n; i++ {
		if b[i] == 0x10 && b[i+1] == 0x00 {
			obj := binary.BigEndian.Uint32(b[i+2 : i+6])
			vendor := binary.BigEndian.Uint16(b[i+8 : i+10])
			return map[string]string{"protocol": "BACnet/IP", "device_instance": fmt.Sprint(obj & 0x3fffff), "vendor_id": fmt.Sprint(vendor)}, nil
		}
	}
	return nil, fmt.Errorf("invalid BACnet I-Am")
}
