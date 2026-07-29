package udpconversation

import "time"

func (m *Manager) Expire(now time.Time, idle time.Duration) int {
	if idle <= 0 {
		return 0
	}
	expired := 0
	for index := 0; index < m.shardCount; index++ {
		shard := &m.shards[index]
		shard.mu.Lock()
		for key, conversation := range shard.conversations {
			if now.Sub(conversation.LastSeenAt) <= idle {
				continue
			}
			delete(shard.conversations, key)
			if node := shard.lruNodes[key]; node != nil {
				shard.lru.Remove(node)
				delete(shard.lruNodes, key)
			}
			expired++
		}
		shard.mu.Unlock()
	}
	if expired > 0 {
		m.stats.active.Add(^uint64(expired - 1))
		m.stats.expired.Add(uint64(expired))
	}
	return expired
}

func (m *Manager) ExpireIdle(now time.Time) int {
	return m.Expire(now, m.config.IdleTimeout)
}
