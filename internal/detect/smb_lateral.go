package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/smb"
)

func (e *Engine) startSMBLateralWatch(bus *core.EventBus) {
	ch := bus.Subscribe(core.EventSMBObservation)
	go func() {
		for event := range ch {
			if o, ok := event.Data.(smb.Observation); ok {
				e.handleSMBObservation(o)
			}
		}
	}()
}

func (e *Engine) handleSMBObservation(o smb.Observation) {
	if o.IsEncrypted {
		return
	}
	now := o.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	largeTransferThreshold := uint64(e.builtinParameter("builtin.large_controller_transfer", "bytes_threshold", 10*1024*1024))
	if largeTransferThreshold == 0 {
		largeTransferThreshold = 10 * 1024 * 1024
	}
	evidence := map[string]interface{}{"smb_command": o.Command, "share_name": o.ShareName, "file_name": o.FileName, "named_pipe": o.NamedPipe, "bytes": o.Bytes, "message_id": o.MessageID, "session_id": o.SessionID, "tree_id": o.TreeID, "smb_encrypted": o.IsEncrypted, "source_ip": o.ClientIP, "destination_ip": o.ServerIP}

	suspicious, signal, msg := "", "", ""
	if o.Command == "write" && o.IsExecutable {
		suspicious, signal, msg = "critical", "remote_executable_write", fmt.Sprintf("%s wrote executable %s to %s over SMB", o.ClientIP, o.FileName, o.ServerIP)
	}
	if o.Command == "write" && o.IsScript {
		suspicious, signal, msg = "high", "remote_script_write", fmt.Sprintf("%s wrote script %s to %s over SMB", o.ClientIP, o.FileName, o.ServerIP)
	}
	pipe := strings.ToLower(o.NamedPipe)
	if pipe != "" && (strings.Contains(pipe, "svcctl") || strings.Contains(pipe, "psexesvc") || strings.Contains(pipe, "atsvc") || strings.Contains(pipe, "winreg")) {
		suspicious, signal, msg = "critical", "suspicious_named_pipe", fmt.Sprintf("%s accessed suspicious SMB named pipe %s on %s", o.ClientIP, o.NamedPipe, o.ServerIP)
	}
	if suspicious != "" {
		// Executable/script transfer and remote-execution pipe activity are hard
		// security signals. If observed during commissioning, quarantine that SMB
		// relationship from both legacy and statistical baselines.
		e.excludePacketFromLearning(core.Packet{SrcIP: o.ClientIP, DstIP: o.ServerIP, SrcPort: o.ClientPort, DstPort: o.ServerPort, L4Protocol: "TCP", Timestamp: now}, "suspicious SMB tool/remote-execution activity")
		evidence["signal"] = signal
		e.raiseBuiltinAlert("builtin.smb_tool_transfer", AlertSMBToolTransfer, suspicious,
			fmt.Sprintf("smb-tool|%s|%s|%s", signal, o.ClientIP, o.ServerIP), msg, o.ClientIP, evidence, now, alertEpisodeGap)
	}
	// Existing broad lateral-movement rule remains useful for admin-share and
	// large-transfer context, but no longer hides tool transfer under one type.
	if e.lateral.Enabled {
		score, confidence, lateralSignal := 0, 0, ""
		lateralMsg := ""
		if o.Command == "tree_connect" && o.IsAdminShare {
			score, confidence, lateralSignal = 80, 85, "admin_share_access"
			lateralMsg = fmt.Sprintf("%s accessed administrative SMB share %s on %s", o.ClientIP, o.ShareName, o.ServerIP)
		}
		if signal != "" {
			score, confidence, lateralSignal = 95, 90, signal
			lateralMsg = msg
		}
		if o.Command == "write" && o.Bytes >= largeTransferThreshold && score < 75 {
			score, confidence, lateralSignal = 75, 75, "large_smb_write"
			lateralMsg = fmt.Sprintf("%s wrote at least %d bytes to %s over SMB", o.ClientIP, o.Bytes, o.ServerIP)
		}
		if lateralSignal != "" {
			ev := map[string]interface{}{}
			for k, v := range evidence {
				ev[k] = v
			}
			ev["lateral_movement_score"], ev["lateral_movement_confidence"] = score, confidence
			e.raiseLateral(lateralSignal, o.ClientIP, o.ServerIP, 445, score, lateralMsg, ev)
		}
	}
	if e.isOTAsset(o.ServerIP) && suspicious != "" {
		e.raiseBuiltinAlert("builtin.smb_into_ot", AlertSMBIntoOT, "high", "smb-ot|"+o.ClientIP+"|"+o.ServerIP,
			fmt.Sprintf("SMB %s activity from %s reached OT asset %s", signal, o.ClientIP, o.ServerIP), o.ClientIP, evidence, now, alertEpisodeGap)
	}
	if e.isOTAsset(o.ServerIP) && o.Command == "write" && o.Bytes >= largeTransferThreshold {
		e.raiseBuiltinAlert("builtin.large_controller_transfer", AlertLargeControllerTransfer, "high", "controller-smb-transfer|"+o.ClientIP+"|"+o.ServerIP,
			fmt.Sprintf("Large SMB transfer (%d bytes) from %s to OT asset %s", o.Bytes, o.ClientIP, o.ServerIP), o.ClientIP, evidence, now, 30*time.Minute)
	}
}
