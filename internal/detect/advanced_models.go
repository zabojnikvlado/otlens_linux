package detect

import (
	"sync"
	"time"
)

type OTValueAnomalyConfig struct {
	Enabled          bool
	MinSamples       int
	ZScoreThreshold  float64
	RateMultiplier   float64
	StuckAfter       time.Duration
	MissingAfter     time.Duration
	ToggleWindow     time.Duration
	ToggleThreshold  int
	UnexpectedWrites bool
	CheckInterval    time.Duration
}

type LateralMovementConfig struct {
	Enabled            bool
	Window             time.Duration
	FanOutThreshold    int
	LargeTransferBytes uint64
	PivotWindow        time.Duration
	AdminPorts         []uint16
}

type C2CorrelationConfig struct {
	Enabled                  bool
	MinScore                 int
	DNSWindow                time.Duration
	NXDomainThreshold        int
	UniqueSubdomainThreshold int
	LongLabelLength          int
}

type otValueState struct {
	Samples              uint64
	Mean, M2             float64
	LastValue            float64
	LastSeen, LastChange time.Time
	TypicalDelta         float64
	ToggleTimes          []time.Time
	DeviceIP             string
	DevicePort           uint16
	AddressSpace         string
	Address              uint32
}

type trafficWindow struct {
	FirstSeen, LastSeen time.Time
	Bytes               uint64
}

type lateralState struct {
	mutex        sync.Mutex
	fanout       map[string]map[string]time.Time
	transfers    map[string]*trafficWindow
	inboundAdmin map[string]map[string]time.Time
}
