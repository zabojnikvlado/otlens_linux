package udpconversation
import "time"
type Conversation struct{ID string; Key Key; Protocol string; StartedAt time.Time; LastSeenAt time.Time; Packets,Bytes,DirectionA,DirectionB uint64}
