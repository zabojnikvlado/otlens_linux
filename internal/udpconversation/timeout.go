package udpconversation

import "time"

// Expire removes conversations idle strictly longer than idle.
func (m *Manager) Expire(now time.Time, idle time.Duration) int {
	if idle <= 0 {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	expired := 0
	for key, conversation := range m.conversations {
		if now.Sub(conversation.LastSeenAt) > idle {
			delete(m.conversations, key)
			if node := m.lruNodes[key]; node != nil {
				m.lru.Remove(node)
				delete(m.lruNodes, key)
			}
			expired++
			m.stats.Expired++
		}
	}
	return expired
}

func (m *Manager) ExpireIdle(now time.Time) int {
	return m.Expire(now, m.config.IdleTimeout)
}
