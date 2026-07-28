package dcerpc

import (
	"encoding/binary"
	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"testing"
	"time"
)

func TestParseRequest(t *testing.T) {
	d := make([]byte, 24)
	d[0] = 5
	d[1] = 0
	d[2] = 0
	d[3] = 3
	d[4] = 0x10
	binary.LittleEndian.PutUint16(d[8:10], 24)
	binary.LittleEndian.PutUint32(d[12:16], 7)
	binary.LittleEndian.PutUint16(d[22:24], 12)
	o, ok := Parse(core.DCERPCFragment{Timestamp: time.Now(), NamedPipe: `\\PIPE\\svcctl`, Data: d})
	if !ok || o.CallID != 7 || o.Opnum != 12 || o.InterfaceHint != "service_control_manager" {
		t.Fatalf("%+v", o)
	}
}
