package capture

import "time"

type Packet struct {
	Timestamp time.Time

	SourceIP string

	DestinationIP string

	Protocol string

	Length int
}
