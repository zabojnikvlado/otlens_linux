package smb

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/streamproto"
)

const maxObservations = 5000

type Engine struct {
	bus           *core.EventBus
	mu            sync.RWMutex
	observations  []Observation
	trees         map[string]string
	files         map[string]string
	requests      map[string]Observation
	useStreams    bool
	streamBuffers map[string][]byte
}

func New(bus *core.EventBus, useStreams ...bool) *Engine {
	streamMode := len(useStreams) > 0 && useStreams[0]
	return &Engine{bus: bus, trees: map[string]string{}, files: map[string]string{}, useStreams: streamMode, streamBuffers: map[string][]byte{}, requests: map[string]Observation{}}
}
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.observations = nil
	e.trees = map[string]string{}
	e.files = map[string]string{}
	e.requests = map[string]Observation{}
	e.streamBuffers = map[string][]byte{}
}

func (e *Engine) Start() {
	if e.useStreams {
		ch := e.bus.Subscribe(core.EventTCPStreamData)
		go func() {
			for ev := range ch {
				chunk, ok := ev.Data.(core.TCPStreamChunk)
				if !ok || (chunk.Protocol != "smb" && chunk.SrcPort != 445 && chunk.DstPort != 445 && streamproto.Detect(chunk.Data) != "smb") {
					continue
				}
				e.publish(e.parseStreamChunk(chunk))
			}
		}()
		return
	}
	ch := e.bus.Subscribe(core.EventPacketParsed)
	go func() {
		for ev := range ch {
			p, ok := ev.Data.(core.Packet)
			if !ok || p.L4Protocol != "TCP" || (p.SrcPort != 445 && p.DstPort != 445) || len(p.AppPayload) < 4 {
				continue
			}
			e.publish(e.parsePacket(p))
		}
	}()
}
func (e *Engine) publish(rows []Observation) {
	for _, o := range rows {
		e.mu.Lock()
		e.observations = append(e.observations, o)
		if len(e.observations) > maxObservations {
			e.observations = e.observations[len(e.observations)-maxObservations:]
		}
		e.mu.Unlock()
		e.bus.Publish(core.Event{Type: core.EventSMBObservation, Timestamp: o.Timestamp, Data: o})
	}
}
func (e *Engine) parseStreamChunk(c core.TCPStreamChunk) []Observation {
	k := c.ConnectionID + "|" + c.SrcIP + "|" + utoa(uint64(c.SrcPort))
	e.mu.Lock()
	b := append(e.streamBuffers[k], c.Data...)
	resynced := false
	if c.GapBefore > 0 {
		// A capture gap invalidates any partial NBSS frame. Search for the next
		// plausible NBSS+SMB signature instead of poisoning the stream forever.
		b = resyncSMB(b)
		resynced = true
	}
	if len(b) > 8<<20 {
		b = b[len(b)-(8<<20):]
	}
	var records [][]byte
	for len(b) >= 4 {
		n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if b[0] != 0 || n <= 0 {
			b = b[1:]
			continue
		}
		if n > 8<<20 {
			b = b[1:]
			continue
		}
		if len(b) < 4+n {
			break
		}
		records = append(records, append([]byte(nil), b[4:4+n]...))
		b = b[4+n:]
	}
	e.streamBuffers[k] = b
	e.mu.Unlock()
	p := core.Packet{SrcIP: c.SrcIP, DstIP: c.DstIP, SrcPort: c.SrcPort, DstPort: c.DstPort, L4Protocol: "TCP", Timestamp: c.Timestamp}
	var out []Observation
	for _, r := range records {
		rows := e.parseRecord(p, r)
		for i := range rows {
			rows[i].StreamGapped = c.Gapped || c.GapBefore > 0
			rows[i].StreamResynced = resynced
		}
		out = append(out, rows...)
	}
	return out
}
func resyncSMB(b []byte) []byte {
	for i := 0; i+8 <= len(b); i++ {
		if b[i] == 0 && (string(b[i+4:i+8]) == "\xfeSMB" || string(b[i+4:i+8]) == "\xfdSMB") {
			n := int(b[i+1])<<16 | int(b[i+2])<<8 | int(b[i+3])
			if n > 0 && n <= 8<<20 {
				return b[i:]
			}
		}
	}
	if len(b) > 7 {
		return b[len(b)-7:]
	}
	return b
}

func (e *Engine) GetObservations() []Observation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Observation, len(e.observations))
	copy(out, e.observations)
	return out
}

func (e *Engine) parsePacket(p core.Packet) []Observation {
	data := p.AppPayload
	// NetBIOS Session Service framing: type + 3-byte length. A capture may contain multiple records.
	var out []Observation
	for len(data) >= 4 {
		n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		if data[0] == 0 && n <= len(data)-4 {
			if n == 0 {
				break
			}
			out = append(out, e.parseRecord(p, data[4:4+n])...)
			data = data[4+n:]
			continue
		}
		out = append(out, e.parseRecord(p, data)...)
		break
	}
	return out
}
func (e *Engine) parseRecord(p core.Packet, data []byte) []Observation {
	if len(data) < 4 {
		return nil
	}
	client, server, dir := p.SrcIP, p.DstIP, "client_to_server"
	cp, sp := p.SrcPort, p.DstPort
	if p.SrcPort == 445 {
		client, server = p.DstIP, p.SrcIP
		cp, sp = p.DstPort, p.SrcPort
		dir = "server_to_client"
	}
	if string(data[:4]) == "\xfdSMB" {
		return []Observation{{Timestamp: p.Timestamp, ClientIP: client, ServerIP: server, ClientPort: cp, ServerPort: sp, Command: "encrypted_transform", Direction: dir, Bytes: uint64(len(data)), IsEncrypted: true}}
	}
	if string(data[:4]) != "\xfeSMB" || len(data) < 64 {
		return nil
	}
	var out []Observation
	for off := 0; off+64 <= len(data) && string(data[off:off+4]) == "\xfeSMB"; {
		h := data[off:]
		cmd := binary.LittleEndian.Uint16(h[12:14])
		flags := binary.LittleEndian.Uint32(h[16:20])
		next := int(binary.LittleEndian.Uint32(h[20:24]))
		isResp := flags&1 != 0
		o := Observation{Timestamp: p.Timestamp, ClientIP: client, ServerIP: server, ClientPort: cp, ServerPort: sp, Command: commandName(cmd), MessageID: binary.LittleEndian.Uint64(h[24:32]), TreeID: binary.LittleEndian.Uint32(h[36:40]), SessionID: binary.LittleEndian.Uint64(h[40:48]), Direction: dir, IsResponse: isResp}
		if isResp {
			o.Status = binary.LittleEndian.Uint32(h[8:12])
		}
		end := len(h)
		if next > 0 && next < end {
			end = next
		}
		body := h[64:end]
		rkey := requestKey(client, server, o.SessionID, o.MessageID)
		var req Observation
		if isResp {
			e.mu.RLock()
			req = e.requests[rkey]
			e.mu.RUnlock()
			if req.Command != "" {
				o.RequestMatched = true
				o.RequestCommand = req.Command
				o.ShareName = req.ShareName
				o.FileName = req.FileName
				o.NamedPipe = req.NamedPipe
			}
		}
		e.enrich(&o, cmd, body)
		if !isResp {
			e.mu.Lock()
			e.requests[rkey] = o
			e.mu.Unlock()
		} else if req.Command != "" {
			e.mu.Lock()
			delete(e.requests, rkey)
			if cmd == 3 && o.Status == 0 && req.ShareName != "" {
				e.trees[key(o.SessionID, uint64(o.TreeID))] = req.ShareName
				o.ShareName = req.ShareName
			}
			if cmd == 5 && o.Status == 0 && (o.FileIDPersistent != 0 || o.FileIDVolatile != 0) {
				name := req.FileName
				if name != "" {
					e.files[key(o.FileIDPersistent, o.FileIDVolatile)] = name
					o.FileName = name
				}
			}
			e.mu.Unlock()
		}
		classify(&o)
		e.handoffDCERPC(p, &o, cmd, body)
		out = append(out, o)
		if next <= 0 || off+next <= off || off+next >= len(data) {
			break
		}
		off += next
	}
	return out
}
func (e *Engine) enrich(o *Observation, cmd uint16, b []byte) {
	treeKey := key(o.SessionID, uint64(o.TreeID))
	fileKey := ""
	switch cmd {
	case 3: // TREE_CONNECT
		if !o.IsResponse && len(b) >= 8 {
			off := int(binary.LittleEndian.Uint16(b[4:6])) - 64
			ln := int(binary.LittleEndian.Uint16(b[6:8]))
			o.ShareName = decodeUTF16At(b, off, ln)
			if o.ShareName != "" {
				e.mu.Lock()
				e.trees[treeKey] = o.ShareName
				e.mu.Unlock()
			}
		}
	case 5: // CREATE
		if !o.IsResponse && len(b) >= 48 {
			off := int(binary.LittleEndian.Uint16(b[44:46])) - 64
			ln := int(binary.LittleEndian.Uint16(b[46:48]))
			o.FileName = decodeUTF16At(b, off, ln)
		}
		if o.IsResponse && len(b) >= 80 {
			persistent := binary.LittleEndian.Uint64(b[64:72])
			volatile := binary.LittleEndian.Uint64(b[72:80])
			o.FileIDPersistent, o.FileIDVolatile = persistent, volatile
			fileKey = key(persistent, volatile)
		}
	case 8: // READ
		if !o.IsResponse && len(b) >= 32 {
			o.Bytes = uint64(binary.LittleEndian.Uint32(b[4:8]))
			o.FileIDPersistent, o.FileIDVolatile = binary.LittleEndian.Uint64(b[16:24]), binary.LittleEndian.Uint64(b[24:32])
			fileKey = key(o.FileIDPersistent, o.FileIDVolatile)
		}
		if o.IsResponse && len(b) >= 8 {
			o.Bytes = uint64(binary.LittleEndian.Uint32(b[4:8]))
		}
	case 9: // WRITE
		if !o.IsResponse && len(b) >= 32 {
			o.Bytes = uint64(binary.LittleEndian.Uint32(b[4:8]))
			o.FileIDPersistent, o.FileIDVolatile = binary.LittleEndian.Uint64(b[16:24]), binary.LittleEndian.Uint64(b[24:32])
			fileKey = key(o.FileIDPersistent, o.FileIDVolatile)
		}
		if o.IsResponse && len(b) >= 8 {
			o.Bytes = uint64(binary.LittleEndian.Uint32(b[4:8]))
		}
	case 6: // CLOSE
		if !o.IsResponse && len(b) >= 24 {
			o.FileIDPersistent, o.FileIDVolatile = binary.LittleEndian.Uint64(b[8:16]), binary.LittleEndian.Uint64(b[16:24])
			fileKey = key(o.FileIDPersistent, o.FileIDVolatile)
		}
	}
	e.mu.RLock()
	if o.ShareName == "" {
		o.ShareName = e.trees[treeKey]
	}
	if o.FileName == "" && fileKey != "" {
		o.FileName = e.files[fileKey]
	}
	e.mu.RUnlock()
	if cmd == 5 && !o.IsResponse && o.FileName != "" { // best-effort: associate request name by message until response is seen
		e.mu.Lock()
		e.files[key(o.SessionID, o.MessageID)] = o.FileName
		e.mu.Unlock()
	}
	if cmd == 5 && o.IsResponse && fileKey != "" {
		e.mu.Lock()
		if n := e.files[key(o.SessionID, o.MessageID)]; n != "" {
			e.files[fileKey] = n
			o.FileName = n
		}
		e.mu.Unlock()
	}
	// Classification is performed after request/response correlation.
}
func (e *Engine) handoffDCERPC(p core.Packet, o *Observation, cmd uint16, body []byte) {
	if cmd != 9 || o.IsResponse || o.NamedPipe == "" || len(body) < 32 {
		return
	}
	off := int(binary.LittleEndian.Uint16(body[2:4])) - 64
	ln := int(binary.LittleEndian.Uint32(body[4:8]))
	if off < 0 || ln <= 0 || off+ln > len(body) {
		return
	}
	data := append([]byte(nil), body[off:off+ln]...)
	if len(data) < 16 || data[0] != 5 || data[1] != 0 {
		return
	}
	f := core.DCERPCFragment{Timestamp: o.Timestamp, ConnectionID: p.SrcIP + ":" + utoa(uint64(p.SrcPort)) + "-" + p.DstIP + ":" + utoa(uint64(p.DstPort)), ClientIP: o.ClientIP, ServerIP: o.ServerIP, NamedPipe: o.NamedPipe, Data: data}
	e.bus.Publish(core.Event{Type: core.EventDCERPCFragment, Timestamp: o.Timestamp, Data: f})
}

func classify(o *Observation) {
	s := strings.ToUpper(strings.TrimSpace(o.ShareName))
	o.IsAdminShare = strings.HasSuffix(s, "\\ADMIN$") || strings.HasSuffix(s, "\\C$") || strings.HasSuffix(s, "\\IPC$") || s == "ADMIN$" || s == "C$" || s == "IPC$"
	name := strings.ToLower(o.FileName)
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".exe", ".dll", ".sys", ".msi", ".scr", ".com":
		o.IsExecutable = true
	case ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".wsf":
		o.IsScript = true
	}
	if strings.Contains(strings.ToLower(o.ShareName), "ipc$") && o.FileName != "" {
		o.NamedPipe = o.FileName
	}
}
func decodeUTF16At(body []byte, off, ln int) string {
	if off < 0 || ln <= 0 || off+ln > len(body) || ln%2 != 0 {
		return ""
	}
	u := make([]uint16, ln/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(body[off+i*2 : off+i*2+2])
	}
	return strings.Trim(strings.ReplaceAll(string(utf16.Decode(u)), "/", "\\"), "\x00")
}
func requestKey(client, server string, session, message uint64) string {
	return client + "|" + server + "|" + key(session, message)
}
func key(a, b uint64) string { return strings.Join([]string{utoa(a), utoa(b)}, "|") }
func utoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
func commandName(c uint16) string {
	m := map[uint16]string{0: "negotiate", 1: "session_setup", 3: "tree_connect", 4: "tree_disconnect", 5: "create", 6: "close", 8: "read", 9: "write", 11: "ioctl", 13: "echo", 14: "query_directory", 16: "query_info", 17: "set_info"}
	if s := m[c]; s != "" {
		return s
	}
	return "command_" + utoa(uint64(c))
}
