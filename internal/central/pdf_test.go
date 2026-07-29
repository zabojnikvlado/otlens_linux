package central

import (
	"bytes"
	"regexp"
	"strconv"
	"testing"
)

func TestBasicPDFHasValidObjectTable(t *testing.T) {
	pdf := reportPDF("<h1>OTLens report</h1><p>Second line</p>", "test-report")
	if !bytes.HasPrefix(pdf, []byte("%PDF-1.4")) {
		t.Fatal("missing PDF header")
	}
	if !bytes.HasSuffix(pdf, []byte("%%EOF\n")) {
		t.Fatal("missing PDF EOF marker")
	}
	root := regexp.MustCompile(`/Root\s+(\d+)\s+0\s+R`).FindSubmatch(pdf)
	if len(root) != 2 || string(root[1]) != "1" {
		t.Fatalf("unexpected catalog root: %q", root)
	}
	xref := regexp.MustCompile(`startxref\s+(\d+)`).FindSubmatch(pdf)
	if len(xref) != 2 {
		t.Fatal("missing startxref")
	}
	offset, err := strconv.Atoi(string(xref[1]))
	if err != nil || offset < 0 || offset >= len(pdf) {
		t.Fatalf("invalid xref offset %q", xref[1])
	}
	if !bytes.HasPrefix(pdf[offset:], []byte("xref\n")) {
		t.Fatalf("startxref points to %q, not xref", pdf[offset:offset+4])
	}
	for _, object := range [][]byte{
		[]byte("1 0 obj\n<< /Type /Catalog"),
		[]byte("2 0 obj\n<< /Type /Pages"),
		[]byte("3 0 obj\n<< /Type /Font"),
		[]byte("4 0 obj\n<< /Type /Font"),
		[]byte("5 0 obj\n<< /Type /Page"),
	} {
		if !bytes.Contains(pdf, object) {
			t.Fatalf("missing object %q", object)
		}
	}
}

func TestReportPlainTextRemovesStyleAndScriptContents(t *testing.T) {
	got := reportPlainText(`<html><head><style>body{color:red}</style><script>alert("x")</script></head><body><h1>OTLens report</h1><p>Healthy</p></body></html>`)
	if bytes.Contains([]byte(got), []byte("body{")) || bytes.Contains([]byte(got), []byte("alert(")) {
		t.Fatalf("style or script content leaked into report text: %q", got)
	}
	if !bytes.Contains([]byte(got), []byte("OTLens report")) || !bytes.Contains([]byte(got), []byte("Healthy")) {
		t.Fatalf("report content missing: %q", got)
	}
}
