package ics

import (
	"encoding/binary"
	"fmt"

	"github.com/zabojnikvlado/otlens/internal/core"
)

// modbusFunctionNames maps Modbus function codes to readable names.
// Reference: Modbus Application Protocol V1.1b3.
var modbusFunctionNames = map[uint8]string{
	1:  "ReadCoils",
	2:  "ReadDiscreteInputs",
	3:  "ReadHoldingRegisters",
	4:  "ReadInputRegisters",
	5:  "WriteSingleCoil",
	6:  "WriteSingleRegister",
	7:  "ReadExceptionStatus",
	15: "WriteMultipleCoils",
	16: "WriteMultipleRegisters",
	17: "ReportServerID",
	22: "MaskWriteRegister",
	23: "ReadWriteMultipleRegisters",
	43: "EncapsulatedInterfaceTransport",
}

func modbusFunctionName(fc uint8) string {

	if name, ok := modbusFunctionNames[fc]; ok {
		return name
	}

	return fmt.Sprintf("Unknown(%d)", fc)
}

// parseModbus decodes a Modbus/TCP ADU: a 7-byte MBAP header
// (Transaction ID, Protocol ID, Length, Unit ID) followed by the
// PDU (function code + data). modbusPort is the configured server
// port (see Engine.ModbusPort) — used only to tell request from
// response (see IsResponse below); it has no bearing on whether this
// looks like Modbus at all, since Engine.decode already only calls
// this for traffic on that port in the first place.
func parseModbus(packet core.Packet, modbusPort uint16) (Message, bool) {

	data := packet.AppPayload

	// 7-byte MBAP header + at least 1 byte function code.
	if len(data) < 8 {
		return Message{}, false
	}

	protocolID := binary.BigEndian.Uint16(data[2:4])

	// The Modbus protocol identifier is always 0 — a cheap sanity
	// check that this really is Modbus and not some other traffic
	// that happens to use port 502.
	if protocolID != 0 {
		return Message{}, false
	}

	unitID := data[6]
	pdu := data[7:]

	fc := pdu[0]
	isException := fc&0x80 != 0
	baseFC := fc &^ 0x80

	msg := newMessage(packet, "Modbus")

	msg.UnitID = unitID
	msg.FunctionCode = baseFC
	msg.FunctionName = modbusFunctionName(baseFC)
	msg.IsException = isException

	// A response is sent FROM the server, i.e. its Ethernet/IP source
	// is the server's own well-known port — the request is the
	// reverse (server is the destination). Without this, every
	// caller downstream that branches on IsResponse (store.Engine's
	// device-IP resolution, most notably) would silently default to
	// treating every Modbus message as a request, misattributing
	// every response's actual device identity to whichever client
	// happened to be polling it — a different address:ephemeral-port
	// for every single TCP connection, fragmenting what's really one
	// device's history across many bogus "devices".
	msg.IsResponse = packet.SrcPort == modbusPort

	body := pdu[1:]

	if isException {

		if len(body) >= 1 {
			msg.Details["exception_code"] = body[0]
		}

	} else {

		decodeModbusData(baseFC, body, msg.Details)
	}

	return msg, true
}

// decodeModbusData pulls out the handful of fields that matter for
// monitoring purposes (address, quantity, actual value read/written)
// without trying to fully reconstruct request vs. response framing —
// request/response correlation across transaction IDs isn't
// implemented, so for a multi-register/coil read (quantity > 1) the
// decoded values are returned as a plain list without per-address
// attribution (the response alone doesn't carry addresses — only the
// matching request does).
func decodeModbusData(fc uint8, data []byte, details map[string]any) {

	switch fc {

	case 1, 2: // Read Coils / Read Discrete Inputs

		if len(data) == 4 {
			// Request: starting address + quantity.
			details["address"] = binary.BigEndian.Uint16(data[0:2])
			details["quantity"] = binary.BigEndian.Uint16(data[2:4])
		} else if len(data) >= 1 {
			// Response: leading byte count + bit-packed values
			// (LSB-first within each byte, per the Modbus spec).
			details["byte_count"] = data[0]
			details["value"] = decodeModbusBits(data[1:], data[0])
		}

	case 3, 4: // Read Holding Registers / Read Input Registers

		if len(data) == 4 {
			details["address"] = binary.BigEndian.Uint16(data[0:2])
			details["quantity"] = binary.BigEndian.Uint16(data[2:4])
		} else if len(data) >= 1 {
			// Response: leading byte count + 16-bit register values.
			details["byte_count"] = data[0]
			details["value"] = decodeModbusRegisters(data[1:], data[0])
		}

	case 5: // Write Single Coil

		if len(data) == 4 {
			// Per spec, a coil write value is always 0xFF00 (ON) or
			// 0x0000 (OFF) — never an arbitrary number. Decoding as
			// bool matches how coils are represented everywhere else
			// (ReadCoils responses, WriteMultipleCoils — both via
			// decodeModbusBits) instead of showing a raw number like
			// 65280 for what's really just "true".
			details["address"] = binary.BigEndian.Uint16(data[0:2])
			details["value"] = data[2] == 0xFF
		}

	case 6: // Write Single Register

		if len(data) == 4 {
			details["address"] = binary.BigEndian.Uint16(data[0:2])
			details["value"] = binary.BigEndian.Uint16(data[2:4])
		}

	case 15, 16: // Write Multiple Coils / Write Multiple Registers

		if len(data) >= 4 {

			details["address"] = binary.BigEndian.Uint16(data[0:2])
			details["quantity"] = binary.BigEndian.Uint16(data[2:4])

			// The response to a WriteMultiple* request is exactly these
			// 4 bytes (starting address + quantity echoed back) — the
			// device doesn't repeat the values it was told to write, it
			// just confirms it accepted them. The request has a byte
			// count + the actual value list appended after that, which
			// is what we actually want to show as "what's being
			// written" — a length check alone tells us which framing
			// we're looking at.
			if len(data) > 5 {

				byteCount := data[4]
				values := data[5:]

				if fc == 16 {
					details["value"] = decodeModbusRegisters(values, byteCount)
				} else {
					details["value"] = decodeModbusBits(values, byteCount)
				}
			}
		}

	case 22: // MaskWriteRegister

		// Request and response share the same 6-byte layout: Reference
		// Address, AND_Mask, OR_Mask — the device applies
		// (current_value AND and_mask) OR (or_mask AND NOT and_mask),
		// so this is a write even though the device has to read the
		// current value internally to compute it.
		if len(data) == 6 {
			details["address"] = binary.BigEndian.Uint16(data[0:2])
			details["and_mask"] = binary.BigEndian.Uint16(data[2:4])
			details["or_mask"] = binary.BigEndian.Uint16(data[4:6])
		}
	}
}

// decodeModbusRegisters unpacks a run of 16-bit big-endian register
// values (Holding/Input Register reads, WriteMultipleRegisters
// writes). byteCount is the wire-declared length — trusted over
// len(data) where they disagree, since it's what the sender actually
// intended (a truncated capture would show up as fewer decoded
// values, not a panic).
func decodeModbusRegisters(data []byte, byteCount uint8) []uint16 {

	n := int(byteCount)

	if n > len(data) {
		n = len(data)
	}

	count := n / 2

	values := make([]uint16, 0, count)

	for i := 0; i < count; i++ {
		values = append(values, binary.BigEndian.Uint16(data[i*2:i*2+2]))
	}

	return values
}

// decodeModbusBits unpacks a run of bit-packed coil/discrete-input
// values (Read Coils/Discrete Inputs responses, WriteMultipleCoils
// writes) — each byte holds up to 8 bits, LSB first, per the Modbus
// spec. There's no way to know from the wire data alone how many of
// the final byte's 8 bits are "real" versus padding, so this returns
// every bit in every byteCount bytes rather than trying to trim to
// an exact requested quantity (the caller has that separately, in
// "quantity", if it needs to truncate for display).
func decodeModbusBits(data []byte, byteCount uint8) []bool {

	n := int(byteCount)

	if n > len(data) {
		n = len(data)
	}

	bits := make([]bool, 0, n*8)

	for i := 0; i < n; i++ {

		b := data[i]

		for bit := 0; bit < 8; bit++ {
			bits = append(bits, b&(1<<uint(bit)) != 0)
		}
	}

	return bits
}
