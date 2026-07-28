package streamproto

import "testing"

func TestDetectSMBOnNonStandardPortPayload(t *testing.T) {
	b := append([]byte{0, 0, 0, 64}, []byte{0xfe, 'S', 'M', 'B'}...)
	if Detect(b) != "smb" {
		t.Fatal(Detect(b))
	}
}
