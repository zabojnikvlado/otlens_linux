# OTLens — pravidlá detekcie (alerty)

Ako fungujú existujúce pravidlá, kde presne žijú, a ako jednoducho
pridať nové. Toto je doplnkový dokument k `DOCUMENTATION.md` — tu je
fókus výhradne na `internal/detect`.

---

## 1. Princíp

Každé pravidlo je **nezávislý, samostatný súbor** v `internal/detect/`,
ktorý:

1. Odoberá (subscribe) jeden konkrétny event z `core.EventBus`
2. Vyhodnotí, či je pozorovaná udalosť "podozrivá"
3. Ak áno, postaví **dedup kľúč** a vytvorí/aktualizuje `Alert`

Všetky pravidlá zdieľajú **rovnaký `Alert` model** (`alert.go`) a
**rovnakú infraštruktúru** (`engine.go`) — mapu alertov, mutex,
Approve/Confirm workflow, retention pruning a logovanie. Central prijíma
normalizovaný alert cez telemetry pipeline, takže nové pravidlo nepotrebuje
špeciálny endpoint ani samostatnú UI implementáciu.

---

## 2. Existujúce pravidlá

| Súbor | Pravidlo (`AlertType`) | Odoberá event | Kľúčované podľa |
|---|---|---|---|
| `arpspoof.go` | `arp_spoof` — konflikt IP↔MAC | `core.EventPacketParsed` | IP + stará/nová MAC |
| `baseline.go` | `new_communication` — komunikácia mimo naučeného vzoru | `core.EventPacketParsed` | protokol + dvojica zariadení |
| `ics_policy.go` + protocol parsers | protocol-aware OT semantics: unauthorized command/write, program/mode/config/time changes, command burst, sequence violations, reporting loss, malformed bursts | `core.EventICSMessage` / `core.EventICSParseError` | source→target authority + protocol/function/context |
| `asset_unconfirmed.go` | `new_asset` — nové zariadenie po baseline learningu | `core.EventAssetUnconfirmed` (z `asset` enginu) | MAC zariadenia |
| `value_out_of_range.go` | `value_out_of_range` — hodnota mimo naučeného rozsahu | `core.EventValueOutOfRange` (zo `store` enginu) | konkrétny Tag |
| `honeypot.go` | `honeypot_lateral_movement` (critical) — honeypot iniciuje odchádzajúcu komunikáciu **smerom na inú internú (private) adresu**; `honeypot_probed` (medium) — niekto sa pripojil na honeypot | `core.EventPacketParsed` | smer + src + dst |
| `external_communication.go` | `external_communication` (medium) — private adresa komunikuje so skutočnou verejnou unicast internetovou adresou. Multicast (napr. `224.0.0.22`), broadcast, link-local, CGNAT a documentation/benchmark ranges sa ignorujú. Dedup podľa internej IP + smeru + verejného peer scope (/24 IPv4 alebo /64 IPv6), aby CDN nevytvorilo alert na každú IP, ale approval jedného cieľa nepotlačil celý internet | `core.EventPacketParsed` | interná IP |
| `segmentation.go` | `segmentation_violation` (high) — explicitná source-zone → destination-zone/protocol policy je porušená; Purdue max-level-jump zostáva fallback. Vypnuté defaultne v `config.yaml` (`detect.segmentation.enabled`/`vlanlevels`/`maxleveljump`), ale nastavenie VLAN levelu z Network Segmentation tabu v Central to živo zapne/aktualizuje bez potreby meniť config.yaml — pozri `DOCUMENTATION.md` | `core.EventPacketParsed` | src+dst IP |
| `reconnaissance.go` | `reconnaissance` (high) — zdrojová IP kontaktovala priveľa rôznych hostov (`detect.reconnaissance.hostscanthreshold`) alebo priveľa rôznych portov na jednom hoste (`portscanthreshold`) v rolling okne (`window`, default 60s). **Zapnuté defaultne** — legitímny host, čo má hovoriť s mnohými (monitoring server, DNS resolver), môže potrebovať vyšší threshold alebo suppression | `core.EventPacketParsed` | zdrojová IP |
| `c2beacon.go` | `c2_beacon` (critical) — interná IP sa pripája na externú IP+port v podozrivo pravidelnom intervale (beacon pattern typický pre C2 malware). Meria sa cez TCP SYN pakety (nie SYN,ACK), potrebuje aspoň `minsamples` pokusov, meria koeficient variácie (stddev/mean) intervalov medzi nimi. **Behaviorálna heuristika, nie known-bad-IP match** — legitímna periodická externá služba (license check-in, monitoring agent) môže tiež spustiť tento alert, ak je jej časovanie dostatočne pravidelné | `core.EventPacketParsed` (TCP SYN) | src IP + dst IP + dst port |

`honeypot.go` je trochu iný než ostatné pravidlá — navyše odoberá aj
`core.EventHoneypotCleared` (z `asset` enginu, publikovaný keď sa
zariadenie na nakonfigurovanej honeypot IP odsťahuje na inú IP, napr.
DHCP). Pri tomto evente `clearHoneypotAlerts()` zmaže všetky
nepotvrdené (`AlertStatusNew`) honeypot alerty pre danú IP — už
preverené (`approved`/`confirmed`) alerty ostávajú netknuté. Toto je
jediné miesto v `internal/detect`, kde sa alert maže namiesto len
vytvára/aktualizuje.

Spoločné súbory (nie samostatné pravidlá):

| Súbor | Obsah |
|---|---|
| `alert.go` | `AlertType`/`AlertStatus` konštanty, `Alert` struct |
| `engine.go` | `Engine` struct, `Start()` (registruje všetky watch funkcie), `logNewAlert()`, Approve/Confirm/Delete/Prune, perzistencia |

---

## 3. Anatómia pravidla

Nasledujúci blok je **legacy shape** pre jednoduchý deduplikovaný alert. Nové built-in rules nemajú kopírovať tento catch-all vzor; používajú `raiseBuiltinAlert()` a protokolové/policy helpery, aby sa jednotne aplikovali enabled/simulation/severity/suppression/schedule/threshold policy. Pre aktuálny katalóg pozri `docs/BUILTIN_RULE_CATALOG.md`.

```go
package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/ics"
)

func (e *Engine) handleICS(msg ics.Message) {

	relevant, _ := msg.Details["security_relevant"].(bool)

	if !relevant {
		return
	}

	// Dedup kľúč — rovnaký nález (rovnaký protokol+funkcia+cieľ) len
	// aktualizuje Count/LastSeen na existujúcom alerte namiesto
	// vytvorenia nového pri každom výskyte.
	key := fmt.Sprintf(
		"ics|%s|%s|%s:%d",
		msg.Protocol,
		msg.FunctionName,
		msg.DstIP,
		msg.DstPort,
	)

	now := time.Now()

	e.mutex.Lock()
	defer e.mutex.Unlock()

	alert, exists := e.alerts[key]

	if !exists {

		alert = &Alert{
			ID: key,

			Type:     AlertICSCriticalOperation,
			Severity: "critical",
			Message: fmt.Sprintf(
				"%s %s directed at %s:%d",
				msg.Protocol, msg.FunctionName, msg.DstIP, msg.DstPort,
			),

			IP: msg.DstIP,

			FirstSeen: now,
			Status:    AlertStatusNew,
		}

		e.alerts[key] = alert

		e.logNewAlert(alert)
	}

	alert.LastSeen = now
	alert.Count++
}
```

A napojenie v `engine.go`'s `Start()`:

```go
func (e *Engine) startICSWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventICSMessage)

	go func() {

		for event := range ch {

			msg, ok := event.Data.(ics.Message)

			if !ok {
				continue
			}

			e.handleICS(msg)
		}

	}()

}
```

### Prečo je to takto navrhnuté

- **`e.logNewAlert(alert)`** sa volá **len raz**, pri vytvorení nového
  záznamu (vnútri `if !exists { ... }`) — nie pri každom opakovanom
  výskyte. Toto jedno volanie automaticky:
  - zaloguje (`logger.Log.Warn`)
- **Dedup kľúč** je to najdôležitejšie rozhodnutie pri návrhu nového
  pravidla — určuje, čo znamená "ten istý nález". Príliš úzky kľúč
  (napr. vrátane presného timestampu) by vytváral nový alert pri
  každom pakete. Príliš široký kľúč (napr. len IP adresa) by zlial
  dokopy nálezy, ktoré by mali byť oddelené.
- **`e.mutex.Lock()`** sa drží počas celej kontroly-a-zápisu (nie len
  pri zápise) — inak by dva súbežné pakety mohli vytvoriť dva
  duplicitné alerty pre ten istý nález (race condition).

---

## 4. Ako pridať nové pravidlo — krok za krokom

Príklad: alert pri podozrivo veľkom objeme dát z jedného zariadenia
za krátky čas.

### Krok 1 — nový súbor `internal/detect/traffic_volume.go`

```go
package detect

import (
	"fmt"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/core"
)

func (e *Engine) startTrafficVolumeWatch(bus *core.EventBus) {

	ch := bus.Subscribe(core.EventPacketParsed)

	go func() {

		for event := range ch {

			packet, ok := event.Data.(core.Packet)

			if !ok {
				continue
			}

			e.handleTrafficVolume(packet)
		}

	}()

}

func (e *Engine) handleTrafficVolume(packet core.Packet) {

	// ... tvoja logika: napr. priebežný počítač bajtov za posledných
	// N sekúnd na SrcIP, porovnanie s prahom ...

	if !suspicious {
		return
	}

	key := fmt.Sprintf("volume|%s", packet.SrcIP)

	now := time.Now()

	e.mutex.Lock()
	defer e.mutex.Unlock()

	alert, exists := e.alerts[key]

	if !exists {

		alert = &Alert{
			ID: key,

			Type:     AlertHighTrafficVolume,
			Severity: "medium",
			Message:  fmt.Sprintf("%s generated unusually high traffic volume", packet.SrcIP),

			IP: packet.SrcIP,

			FirstSeen: now,
			Status:    AlertStatusNew,
		}

		e.alerts[key] = alert

		e.logNewAlert(alert)
	}

	alert.LastSeen = now
	alert.Count++
}
```

### Krok 2 — nová `AlertType` konštanta v `alert.go`

```go
const (
	...
	// AlertHighTrafficVolume fires when a device generates an
	// unusually high traffic volume in a short window.
	AlertHighTrafficVolume AlertType = "high_traffic_volume"
)
```

### Krok 3 — registrácia v `engine.go`'s `Start()`

```go
func (e *Engine) Start(bus *core.EventBus) {
	...
	e.startARPWatch(bus)
	e.startICSWatch(bus)
	e.startBaselineWatch(bus)
	e.startAssetUnconfirmedWatch(bus)
	e.startValueOutOfRangeWatch(bus)
	e.startTrafficVolumeWatch(bus)   // ← nový riadok
}
```

### Hotovo

Nové pravidlo sa **automaticky** objaví:
- v Central Alerts tabe po najbližšej synchronizácii senzora
- v Central telemetry a SIEM pipeline podľa spoločného modelu alertu

**Žiadny ďalší súbor sa meniť nemusí.**

---

## 5. Odkiaľ vybrať vstupný event

| Event | Kedy ho použiť |
|---|---|
| `core.EventPacketParsed` | Potrebuješ dáta na úrovni L2-L4 (IP, port, MAC, veľkosť paketu) — nezávisle od toho, či ide o OT protokol |
| `core.EventICSMessage` | Potrebuješ dekódovaný Modbus/S7comm obsah (function code, adresa, hodnota) |
| Vlastný nový event | Ak logika prirodzene patrí do iného enginu (napr. `flow`/`asset`/`store`) — pozri `core.EventAssetUnconfirmed`/`core.EventValueOutOfRange` ako vzor: payload typ žije v `core`, producent (napr. `store`) ho publikuje, `detect` ho odoberá. Toto udržiava `detect` bez potreby importovať `store`/`asset` priamo. |

---

## 6. Bežné pasce

- **Nezabudni na `e.mutex.Lock()`** okolo celej kontroly-a-zápisu do
  `e.alerts` — nie len okolo samotného zápisu.
- **`Status: AlertStatusNew`** treba nastaviť explicitne pri vytvorení
  — Go-ho nulová hodnota pre string (`""`) nie je jeden z platných
  stavov.
- **Voľ `Severity`** konzistentne s existujúcimi: `"low"` | `"medium"`
  | `"high"` | `"critical"`.
- **Nevolaj `e.logNewAlert()` pri každom výskyte** — len pri vytvorení
  (`if !exists`). Inak sa export/log zaplaví opakovaním toho istého
  nálezu.
- Ak pravidlo potrebuje vedieť o baseline learning stave (napr. "len
  po skončení learningu"), pozri `asset_unconfirmed.go`/
  `value_out_of_range.go` ako vzor — subscribe na
  `core.EventBaselineLearningComplete` a drž si vlastný `bool`
  príznak, nezavolávaj priamo metódy iného enginu.

## Protocol-aware OT operations (v14)

OT operations are normalized before detection into semantic classes such as `read`, `write`, `operate/command`, `program`, `mode`, `config`, `time` and `session`. The old blanket rule no longer turns every "security relevant" parser event into CRITICAL. OPC UA secure-channel lifecycle is session traffic; IEC-104/BACnet time synchronization is evaluated by a dedicated time-source policy; ordinary writes are evaluated by write/command authority. Program download/online edit, controller stop/restart/mode change and device configuration changes have dedicated built-ins.

Read/access authority, command/write authority and time-setting authority are learned separately. A historian that reads a PLC during learning therefore cannot become a writer. Hard-security evidence quarantines the source→target relationship so it cannot be learned by another subscriber in the same event cycle. See `docs/BUILTIN_RULE_CATALOG.md` for the complete catalogue and tunable thresholds.


### Suppression cardinality

Custom rules default to `aggregate`. `suppression.mode: every` is intentionally
a high-cardinality mode: every matching event/packet gets a distinct alert key.
Use it only when per-event alert records are required; otherwise prefer
`aggregate` or `interval` to avoid packet-rate alert growth. The Central rule
editor displays a warning whenever `Every occurrence` is selected.

## Learning quality and trusted behavior baseline (v13)

`baseline.learningduration` is a **minimum** learning window, not a blind deadline. After that minimum OTLens checks baseline maturity (per-asset age/sample count), time-of-day coverage, and whether new communication patterns are still arriving too quickly. Monitoring starts when the readiness gate is satisfied; `baseline.maxlearningmultiplier` is the safety cap for unusually sparse/noisy networks.

The behavior time model no longer requires a full hour-of-week matrix. It learns intra-day buckets plus `weekday/weekend`, shift (`night/day/evening`) and `production/maintenance` context. Optional maintenance windows use UTC expressions such as `weekend@02:00-04:00` or `mon,tue@22:00-23:00`; maintenance behavior is learned separately and is not compared to production behavior.

Hard-security/policy evidence is never allowed to poison the trusted behavior baseline. Threat-intelligence hits, segmentation violations, honeypot activity, critical ICS operations and live custom policy matches quarantine the corresponding learned/candidate flow. The exclusion state is persisted with the behavior snapshot. Public-Internet relationships are also never silently trusted: they are collected only in the shadow baseline and require explicit analyst promotion after sufficient evidence.

After learning, unseen relationships enter a **shadow candidate baseline**. They do not silently modify trusted behavior. Candidates collect observation count and distinct-day evidence and become promotable only after `baseline.candidateminsamples` and `baseline.candidatemindays` are reached. An analyst can promote an eligible candidate from **Network Behavior → Candidate baseline**; candidates with actual hard-security/policy evidence remain quarantined and cannot be promoted.

During learning NBA runs a non-alerting **preview** evaluator (“What would alert now?”). Central shows readiness, mature/learning assets, time coverage, new-pattern rate, excluded security flows, candidate counts and preview anomaly score/count so an operator can judge whether the baseline is actually ready before relying on it.

Statistical behavior uses bounded robust samples (median/MAD and percentiles) with `baseline.minstatsamples` instead of treating a handful of samples as a mature Gaussian distribution. OT process-value learning similarly uses robust percentile/MAD bounds plus a learned value-rate envelope; the learned process model freezes when learning finishes rather than drifting toward later anomalies.
