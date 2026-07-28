// Package dcerpc decodes minimal connection-oriented DCE/RPC metadata handed
// off by SMB named-pipe tracking. It intentionally does not retain RPC payloads.
package dcerpc

import (
	"encoding/binary"
	"strings"
	"sync"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

type Observation struct {
	Timestamp      time.Time `json:"timestamp"`
	ConnectionID   string    `json:"connection_id"`
	ClientIP       string    `json:"client_ip"`
	ServerIP       string    `json:"server_ip"`
	NamedPipe      string    `json:"named_pipe"`
	PacketType     uint8     `json:"packet_type"`
	CallID         uint32    `json:"call_id"`
	Opnum          uint16    `json:"opnum,omitempty"`
	FragmentLength uint16    `json:"fragment_length"`
	FirstFragment  bool      `json:"first_fragment"`
	LastFragment   bool      `json:"last_fragment"`
	InterfaceHint  string    `json:"interface_hint,omitempty"`
}

type Engine struct {
	bus          *core.EventBus
	mu           sync.RWMutex
	observations []Observation
}

func New(bus *core.EventBus) *Engine { return &Engine{bus: bus} }
func (e *Engine) Start() {
	ch := e.bus.Subscribe(core.EventDCERPCFragment)
	go func() {
		for ev := range ch {
			f, ok := ev.Data.(core.DCERPCFragment)
			if !ok {
				continue
			}
			if o, ok := Parse(f); ok {
				e.mu.Lock()
				e.observations = append(e.observations, o)
				if len(e.observations) > 5000 {
					e.observations = e.observations[len(e.observations)-5000:]
				}
				e.mu.Unlock()
				e.bus.Publish(core.Event{Type: core.EventDCERPCObservation, Timestamp: o.Timestamp, Data: o})
			}
		}
	}()
}
func Parse(f core.DCERPCFragment) (Observation, bool) {
	d := f.Data
	if len(d) < 16 || d[0] != 5 || d[1] != 0 {
		return Observation{}, false
	}
	frag := binary.LittleEndian.Uint16(d[8:10])
	if frag < 16 {
		return Observation{}, false
	}
	o := Observation{Timestamp: f.Timestamp, ConnectionID: f.ConnectionID, ClientIP: f.ClientIP, ServerIP: f.ServerIP, NamedPipe: f.NamedPipe, PacketType: d[2], FragmentLength: frag, CallID: binary.LittleEndian.Uint32(d[12:16]), FirstFragment: d[3]&1 != 0, LastFragment: d[3]&2 != 0, InterfaceHint: pipeHint(f.NamedPipe)}
	if d[2] == 0 && len(d) >= 24 {
		o.Opnum = binary.LittleEndian.Uint16(d[22:24])
	}
	return o, true
}
func pipeHint(p string) string {
	s := strings.ToLower(p)
	switch {
	case strings.Contains(s, "svcctl"):
		return "service_control_manager"
	case strings.Contains(s, "samr"):
		return "security_account_manager"
	case strings.Contains(s, "lsarpc"):
		return "local_security_authority"
	case strings.Contains(s, "winreg"):
		return "remote_registry"
	case strings.Contains(s, "atsvc"):
		return "task_scheduler"
	}
	return ""
}
func (e *Engine) GetObservations() []Observation {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Observation, len(e.observations))
	copy(out, e.observations)
	return out
}
