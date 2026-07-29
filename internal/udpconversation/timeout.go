package udpconversation

import "time"

func (m *Manager) Expire(now time.Time,idle time.Duration) int{
m.mu.Lock();defer m.mu.Unlock()
n:=0
for k,c:= range m.conversations{
if now.Sub(c.LastSeenAt)>idle{
delete(m.conversations,k);n++;m.Expired++
}
}
return n
}
