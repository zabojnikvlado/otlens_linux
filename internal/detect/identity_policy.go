package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
	"github.com/zabojnikvlado/otlens_linux/internal/hostname"
)

func (e *Engine) startIdentityPolicyWatch(bus *core.EventBus) {
	ch := bus.Subscribe(core.EventHostnameSeen)
	go func() {
		for event := range ch {
			o, ok := event.Data.(hostname.Observation)
			if !ok || strings.TrimSpace(o.MAC) == "" || strings.TrimSpace(o.Hostname) == "" {
				continue
			}
			e.observeHostnameIdentity(o)
		}
	}()
}

func (e *Engine) observeHostnameIdentity(o hostname.Observation) {
	mac := strings.ToLower(strings.TrimSpace(o.MAC))
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o.Hostname), "."))
	if mac == "" || name == "" {
		return
	}

	e.policyMutex.Lock()
	previous := e.hostnameByMAC[mac]
	if previous == "" || e.behaviorDetectionsSuppressed() {
		e.hostnameByMAC[mac] = name
		e.policyMutex.Unlock()
		return
	}
	e.policyMutex.Unlock()
	if previous == name {
		return
	}

	e.raiseBuiltinAlert("builtin.asset_identity_drift", AlertAssetIdentityDrift, "high",
		fmt.Sprintf("identity-hostname|%s|%s|%s", mac, previous, name),
		fmt.Sprintf("Asset %s changed announced hostname from %s to %s", mac, previous, name), "",
		map[string]interface{}{"mac": mac, "previous_hostname": previous, "new_hostname": name, "source": o.Source}, time.Now(), 30*time.Minute)
}

func (e *Engine) isGatewayAsset(ip string) bool {
	c, ok := e.assetContext(ip)
	if !ok {
		return false
	}
	r := strings.ToLower(c.Role)
	return strings.Contains(r, "gateway") || strings.Contains(r, "router") || strings.Contains(r, "firewall") || strings.Contains(r, "layer 3")
}

func isRedundancyVirtualMAC(mac string) bool {
	s := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"))
	// VRRP IPv4/IPv6 virtual MACs and common HSRP v1/v2 prefixes.
	return strings.HasPrefix(s, "00:00:5e:00:01:") || strings.HasPrefix(s, "00:00:5e:00:02:") ||
		strings.HasPrefix(s, "00:00:0c:07:ac:") || strings.HasPrefix(s, "00:00:0c:9f:f")
}
