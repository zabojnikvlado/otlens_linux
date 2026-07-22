package capture

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"

	"github.com/zabojnikvlado/otlens/internal/logger"
	"go.uber.org/zap"
)

// packetDataSource is the common interface both pcapgo.Reader
// (classic .pcap) and pcapgo.NgReader (.pcapng) implement.
type packetDataSource interface {
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
}

func openFileSource(path string, f *os.File) (packetDataSource, error) {

	if strings.HasSuffix(strings.ToLower(path), ".pcapng") {

		reader, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)

		if err != nil {
			return nil, fmt.Errorf("opening pcapng file failed: %w", err)
		}

		return reader, nil
	}

	reader, err := pcapgo.NewReader(f)

	if err != nil {
		return nil, fmt.Errorf("opening pcap file failed: %w", err)
	}

	return reader, nil
}

// AnalyzeFile reads every packet from a saved .pcap/.pcapng file and
// publishes it through the exact same core.EventPacketCaptured
// pipeline live capture uses — so parsing, ICS decoding, flow/asset
// tracking, and detection all process it identically to live
// traffic. Uses pcapgo (pure Go), so this works even without
// Npcap/libpcap installed. This is a one-shot pass, not a loop — for
// the admin API's "analyze this capture" action.
//
// The caller (the admin API) is responsible for only invoking this
// while live capture is stopped — running both at once would
// interleave two traffic sources into the same pipeline in a way
// that would confusingly mix live and historical data together.
func (e *Engine) AnalyzeFile(path string) (int, error) {

	f, err := os.Open(path)

	if err != nil {
		return 0, fmt.Errorf("opening file %q failed: %w", path, err)
	}

	defer f.Close()

	source, err := openFileSource(path, f)

	if err != nil {
		return 0, err
	}

	count := 0

	for {

		data, ci, err := source.ReadPacketData()

		if err == io.EOF {
			break
		}

		if err != nil {
			return count, fmt.Errorf("reading packet %d failed: %w", count+1, err)
		}

		count++

		// ci.Timestamp is the packet's *original* capture time from
		// the file, not time.Now() — see core.RawFrame's doc comment
		// for why replaying historical data needs to preserve that
		// rather than stamping everything with "right now".
		e.process(data, ci.Timestamp, true)
	}

	logger.Log.Info(
		"Analyzed uploaded pcap file",
		zap.String("file", path),
		zap.Int("packets", count),
	)

	return count, nil
}
