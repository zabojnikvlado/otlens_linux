package ics

import "encoding/binary"

func u16le(b []byte, off int) (uint16, bool) {
	if off < 0 || off+2 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b[off : off+2]), true
}
func u16be(b []byte, off int) (uint16, bool) {
	if off < 0 || off+2 > len(b) {
		return 0, false
	}
	return binary.BigEndian.Uint16(b[off : off+2]), true
}
func u32le(b []byte, off int) (uint32, bool) {
	if off < 0 || off+4 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[off : off+4]), true
}

// setOperation normalizes protocol-specific functions into a small semantic
// vocabulary consumed by the product built-in detectors. "securityRelevant"
// is reserved for intrinsically high-impact operations that deserve the legacy
// ics_critical_operation alert even without policy/baseline context. Routine
// writes/commands are represented explicitly but are not automatically
// "critical" merely because they change process state.
func setOperation(m *Message, class string, isWrite, isCommand, securityRelevant bool) {
	if m == nil {
		return
	}
	m.Details["operation_class"] = class
	if isWrite {
		m.Details["is_write"] = true
	}
	if isCommand {
		m.Details["is_command"] = true
	}
	if securityRelevant {
		m.Details["security_relevant"] = true
	}
	switch class {
	case "program":
		m.Details["is_programming"] = true
	case "mode":
		m.Details["is_mode_change"] = true
	case "time":
		m.Details["is_time_change"] = true
	case "config":
		m.Details["is_config_change"] = true
	}
}
