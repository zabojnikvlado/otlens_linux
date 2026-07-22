package core

import "time"

// RawFrame is the unparsed capture output: exactly the bytes
// gopacket handed back for one frame, with no interpretation
// applied yet. capture.Engine publishes this on EventPacketCaptured;
// internal/parser is what turns it into a Packet.
type RawFrame struct {
	Data []byte

	// Timestamp is when this frame was actually captured — from
	// pcap's own CaptureInfo, not time.Now() at processing time. This
	// matters most when analyzing an uploaded .pcap file (see
	// capture.Engine.AnalyzeFile): the file's packets carry their
	// original historical capture times, and every downstream engine
	// (asset/flow/store/...) should record FirstSeen/LastSeen against
	// that history, not "whenever this happened to get processed" —
	// otherwise replaying an old capture would misleadingly stamp
	// everything with today's date/time.
	Timestamp time.Time

	// FromAnalysis marks a frame that came from a manually-uploaded
	// pcap file (capture.Engine.AnalyzeFile) rather than live capture
	// or IPFIX. Downstream engines use this to exempt the resulting
	// records from age-based retention pruning permanently — Timestamp
	// above is the file's own historical capture time, which can
	// legitimately be older than the retention window (a pcap from
	// last month, analyzed today); without this flag, the very next
	// prune pass after live capture resumes would delete everything
	// the analysis just produced, since pruning has no other way to
	// tell "old because genuinely stale" from "old because it's a
	// deliberately-reviewed historical snapshot".
	FromAnalysis bool
}

