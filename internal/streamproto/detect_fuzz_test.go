package streamproto

import "testing"

func FuzzDetectResultNeverPanics(f *testing.F) {
	f.Add([]byte{0xfe, 'S', 'M', 'B'})
	f.Add([]byte{0, 1, 0, 0, 0, 6, 1, 3})
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := DetectResult(data)
		if r.Confidence > 100 {
			t.Fatalf("invalid confidence %d", r.Confidence)
		}
		if r.Protocol == "" {
			t.Fatal("empty protocol")
		}
	})
}
