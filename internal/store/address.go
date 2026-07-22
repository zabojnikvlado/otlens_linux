package store

import (
	"fmt"

	"github.com/zabojnikvlado/otlens/internal/ics"
)

// extractAddress derives the address-space identity for a decoded
// ICS message, i.e. what makes this "the same variable" across
// repeated polls. Returns ok=false when the message doesn't carry
// enough information to identify a variable (e.g. a bare Ack).
func extractAddress(msg ics.Message) (addressSpace string, address uint32, ok bool) {

	switch msg.Protocol {

	case "Modbus":
		return extractModbusAddress(msg)

	case "S7comm":
		return extractS7Address(msg)

	default:
		return "", 0, false
	}
}

func extractModbusAddress(msg ics.Message) (string, uint32, bool) {

	raw, has := msg.Details["address"]

	if !has {
		return "", 0, false
	}

	addr, ok := raw.(uint16)

	if !ok {
		return "", 0, false
	}

	return modbusAddressSpace(msg.FunctionCode), uint32(addr), true
}

// modbusAddressSpace maps a function code to the Modbus data table
// it operates on. Read and write function codes for the same table
// intentionally map to the same space (e.g. ReadHoldingRegisters and
// WriteSingleRegister both map to "HoldingRegister"), since they can
// address the same underlying variable.
func modbusAddressSpace(fc uint8) string {

	switch fc {

	case 1, 5, 15:
		return "Coil"

	case 2:
		return "DiscreteInput"

	case 3, 6, 16, 22:
		return "HoldingRegister"

	case 4:
		return "InputRegister"

	default:
		return "Unknown"
	}
}

// extractS7Address uses item-level area/DB/address when
// internal/ics's S7 parser managed to decode it (ReadVar/WriteVar Job
// requests using plain S7ANY addressing — see
// parseS7FirstItemAddress's doc comment for what that excludes:
// symbolic/optimized addressing, and responses in general, since a
// response doesn't repeat the address without request/response
// correlation).
//
// Falls back to function-code granularity (all ReadVar calls to a
// device aggregate into one tag, etc.) for anything that fallback
// doesn't cover — this still gives useful poll/change counters and,
// critically, still lets PLCStop/PLCControl show up as their own
// tracked tag even though they have no data-block address at all.
func extractS7Address(msg ics.Message) (string, uint32, bool) {

	if area, hasArea := msg.Details["s7_area"].(string); hasArea {

		if addr, hasAddr := msg.Details["address"].(uint32); hasAddr {

			addressSpace := area

			if area == "DB" {

				if db, hasDB := msg.Details["s7_db"].(uint16); hasDB {
					addressSpace = fmt.Sprintf("DB%d", db)
				}
			}

			return addressSpace, addr, true
		}
	}

	if msg.FunctionName == "" {
		return "", 0, false
	}

	return "Function", uint32(msg.FunctionCode), true
}

// isWriteOperation reports whether a decoded message represents a
// write (control) action rather than a passive read.
func isWriteOperation(msg ics.Message) bool {

	switch msg.Protocol {

	case "Modbus":

		switch msg.FunctionCode {
		case 5, 6, 15, 16, 22:
			// 22 = MaskWriteRegister: modifies a register in place via
			// AND/OR masks — a write, even though it reads the current
			// value internally as part of applying the mask. Omitting
			// it here was a real gap: it used to silently fall through
			// to "Read".
			return true
		}

	case "S7comm":

		return msg.FunctionName == "WriteVar"
	}

	return false
}

// isSecurityRelevant reports whether the ics parser flagged this
// message as inherently high-signal (e.g. S7 PLCStop/PLCControl),
// regardless of whether it also happens to be a "write".
func isSecurityRelevant(msg ics.Message) bool {

	relevant, _ := msg.Details["security_relevant"].(bool)

	return relevant
}
