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
| `icscritical.go` | `ics_critical_operation` — kritická OT operácia (napr. S7 PLCStop) | `core.EventICSMessage` | protokol + funkcia + cieľové zariadenie |
| `asset_unconfirmed.go` | `new_asset` — nové zariadenie po baseline learningu | `core.EventAssetUnconfirmed` (z `asset` enginu) | MAC zariadenia |
| `value_out_of_range.go` | `value_out_of_range` — hodnota mimo naučeného rozsahu | `core.EventValueOutOfRange` (zo `store` enginu) | konkrétny Tag |

Spoločné súbory (nie samostatné pravidlá):

| Súbor | Obsah |
|---|---|
| `alert.go` | `AlertType`/`AlertStatus` konštanty, `Alert` struct |
| `engine.go` | `Engine` struct, `Start()` (registruje všetky watch funkcie), `logNewAlert()`, Approve/Confirm/Delete/Prune, perzistencia |

---

## 3. Anatómia jedného pravidla — `icscritical.go` ako referenčný vzor

Toto je najkratšie a najčistejšie z existujúcich pravidiel (68
riadkov), dobré na kopírovanie:

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

## Extended OT protocol operations

The built-in **Critical ICS Operation** rule now also receives security-relevant events from EtherNet/IP, DNP3, OPC UA, BACnet/IP, IEC 60870-5-104 and PROFINET DCP parsers. Examples include DNP3 Operate/Direct Operate, BACnet WriteProperty and ReinitializeDevice, IEC-104 control commands and clock synchronization, PROFINET DCP Set and selected CIP write-like services.
