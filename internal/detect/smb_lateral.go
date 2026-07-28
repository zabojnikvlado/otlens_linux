package detect

import (
	"fmt"
	"strings"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/smb"
)

func (e *Engine) startSMBLateralWatch(bus *core.EventBus) {
	ch := bus.Subscribe(core.EventSMBObservation)
	go func() {
		for event := range ch {
			o, ok := event.Data.(smb.Observation)
			if !ok || !e.lateral.Enabled {
				continue
			}
			e.handleSMBObservation(o)
		}
	}()
}

func (e *Engine) handleSMBObservation(o smb.Observation) {
	if o.IsEncrypted {
		return
	}
	score, confidence, signal := 0, 0, ""
	msg := ""
	if o.Command == "tree_connect" && o.IsAdminShare {
		score, confidence, signal = 80, 85, "admin_share_access"
		msg = fmt.Sprintf("%s accessed administrative SMB share %s on %s", o.ClientIP, o.ShareName, o.ServerIP)
	}
	if o.Command == "write" && o.IsExecutable {
		score, confidence, signal = 95, 90, "remote_executable_write"
		msg = fmt.Sprintf("%s wrote executable %s to %s over SMB", o.ClientIP, o.FileName, o.ServerIP)
	} else if o.Command == "write" && o.IsScript {
		score, confidence, signal = 90, 88, "remote_script_write"
		msg = fmt.Sprintf("%s wrote script %s to %s over SMB", o.ClientIP, o.FileName, o.ServerIP)
	} else if o.Command == "write" && o.Bytes >= 10*1024*1024 {
		score, confidence, signal = 75, 75, "large_smb_write"
		msg = fmt.Sprintf("%s wrote at least %d bytes to %s over SMB", o.ClientIP, o.Bytes, o.ServerIP)
	}
	pipe := strings.ToLower(o.NamedPipe)
	if pipe != "" && (strings.Contains(pipe, "svcctl") || strings.Contains(pipe, "psexesvc") || strings.Contains(pipe, "atsvc") || strings.Contains(pipe, "winreg")) {
		score, confidence, signal = 98, 92, "suspicious_named_pipe"
		msg = fmt.Sprintf("%s accessed suspicious SMB named pipe %s on %s", o.ClientIP, o.NamedPipe, o.ServerIP)
	}
	if signal == "" {
		return
	}
	evidence := map[string]interface{}{
		"lateral_movement_score": score, "lateral_movement_confidence": confidence,
		"smb_command": o.Command, "share_name": o.ShareName, "file_name": o.FileName,
		"named_pipe": o.NamedPipe, "bytes": o.Bytes, "message_id": o.MessageID,
		"session_id": o.SessionID, "tree_id": o.TreeID, "smb_encrypted": o.IsEncrypted,
	}
	e.raiseLateral(signal, o.ClientIP, o.ServerIP, 445, score, msg, evidence)
}
