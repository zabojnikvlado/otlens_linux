package udpconversation

import (
"sync"
"time"
)

type Manager struct {
mu sync.RWMutex
conversations map[Key]*Conversation
Created uint64
Expired uint64
MaxActive int
}

func NewManager(max int)*Manager{
return &Manager{conversations:make(map[Key]*Conversation),MaxActive:max}
}

func (m *Manager) GetOrCreate(k Key)*Conversation{
m.mu.RLock()
if c:=m.conversations[k]; c!=nil {m.mu.RUnlock(); return c}
m.mu.RUnlock()
m.mu.Lock()
defer m.mu.Unlock()
if c:=m.conversations[k]; c!=nil {return c}
if m.MaxActive>0 && len(m.conversations)>=m.MaxActive {return nil}
c:=&Conversation{Key:k,StartedAt:time.Now(),LastSeenAt:time.Now()}
m.conversations[k]=c
m.Created++
return c
}

func (m *Manager) Stats() Stats{
m.mu.RLock();defer m.mu.RUnlock()
return Stats{ActiveConversations:uint64(len(m.conversations))}
}
