# OTLens — dokumentácia projektu

Lightweight OT Network Intelligence Platform. OTLens zachytáva sieťovú
prevádzku (živo cez Npcap/libpcap, alebo pasívne cez IPFIX export),
parsuje ju až po OT/ICS aplikačnú vrstvu (Modbus, S7comm), sleduje
zariadenia a komunikáciu v sieti, ukladá stav OT premenných
Nozomi-štýlom (bez zaplavenia disku) a deteguje anomálie (ARP
spoofing, odchýlky od naučeného baseline, kritické OT control
operácie, nové zariadenia po baseline learningu). Všetko je vystavené
cez REST API a vlastný webový dashboard.

> Ako fungujú a ako pridať nové pravidlá detekcie (alerty), pozri
> samostatný dokument [DETECTION_RULES.md](DETECTION_RULES.md).

---

## 1. Rýchly štart

### Predpoklady

- Go 1.25+
- Npcap (Windows) alebo libpcap (Linux/macOS) nainštalované —
  **iba** pokiaľ používaš `capture.mode: pcap` (default). Pri
  `capture.mode: ipfix` (pozri nižšie) toto netreba vôbec — je to
  čistý UDP listener.
- Prístup na internet pri prvom builde (kvôli `go.etcd.io/bbolt`)

### Build

```
go get go.etcd.io/bbolt
go mod tidy
go run ./cmd/otlens
```

> **Dôležité:** `go.etcd.io/bbolt` (perzistencia) nie je v `go.mod`
> predvyplnené s presnými hashmi — spusti `go get`/`go mod tidy` raz
> pred prvým buildom, aby si Go doplnil `go.sum` správne.

### Dashboard

Po spustení appky je webové rozhranie na `http://<host>:<port>/ui/`
(default `http://localhost:8080/ui/`). REST API beží na tom istom
porte pod koreňom (`/assets`, `/flows`, ...) — pozri sekciu 5/7.

### Zistenie názvu capture zariadenia (len pcap mód)

```
go run ./cmd/tools/interfaces
```

Vypíše zoznam všetkých zachytávateľných sieťových zariadení (`Name` +
`Description`). Skopíruj presný `Name` (napr.
`\Device\NPF_{GUID}` na Windows) do `configs/config.yaml` →
`capture.interface`, ak sa appka nevie sama trafiť podľa friendly
mena.

### Zdroj dát: pcap vs ipfix

`capture.mode` v configu volí, odkiaľ appka berie dáta:

- **`pcap`** (default) — živé zachytávanie paketov cez
  Npcap/libpcap. Vyžaduje admin/root práva a nainštalovaný
  driver. Vidí **všetko** — payload, MAC adresy, ARP — takže
  fungujú všetky funkcie (Modbus/S7comm dekódovanie, ARP spoofing
  detekcia, MAC-based asset identita).
- **`ipfix`** — appka len počúva na UDP porte (default `4739`) a
  prijíma flow záznamy exportované routerom/switchom/probe. **Žiadne
  admin práva netreba** — nie je to packet capture, len bežný UDP
  socket. Nevýhoda: IPFIX nesie len agregované flow súhrny (kto s
  kým, koľko paketov/bajtov) — **nikdy nie obsah paketu ani MAC
  adresy**. V tomto móde preto nefunguje Modbus/S7comm dekódovanie,
  ARP spoofing detekcia, ani MAC-based asset identita — len Flows
  tab má plnú hodnotu.

### Zastavenie

Appka beží, kým ju nezastavíš (Ctrl+C alebo SIGTERM) — pri zastavení
sa automaticky uloží posledný stav na disk (`Shutdown()` →
`Snapshotter.Close()`). V `pcap` móde sa dá capture zastaviť/spustiť
aj za behu cez Admin tab v dashboarde (pozri sekciu 7), bez reštartu
celej appky.

---

## 2. Architektúra

OTLens je postavený na **event-driven** architektúre: jeden zdieľaný
`core.EventBus` (pub/sub), na ktorý sa nezávisle napájajú jednotlivé
enginy. Žiadny engine nevolá metódy iného enginu priamo — všetka
komunikácia ide cez eventy (výnimka: API vrstva a `persist` vrstva
čítajú stav z enginov na požiadanie, keďže sú to konzumenti, nie
súrodenci v pipeline). Vďaka tomu je možné každý engine vyvíjať,
testovať a nahradiť nezávisle.

```
capture ──EventPacketCaptured──▶ parser ──EventPacketParsed──▶ ┬─▶ asset ◀── hostname (mDNS/DHCP)
   (alebo ipfix ──EventIPFIXFlow──▶ flow priamo)                ├─▶ flow ◀── ipfix (ak capture.mode: ipfix)
                                                                  ├─▶ ics ──EventICSMessage──▶ ┬─▶ store
                                                                  │                              └─▶ detect
                                                                  └─▶ detect (ARP, baseline)

detect ──EventBaselineLearningComplete──▶ asset (rozhoduje o Confirmed pre nové zariadenia)
asset ──EventAssetUnconfirmed──▶ detect (vyvolá "new_asset" Alert)

                                                          api ◀── (číta stav zo všetkých enginov na požiadanie, aj oui pre vendor lookup)
                                                     persist ◀── (periodicky snapshotuje/obnovuje stav všetkých enginov)
```

### Zoznam enginov (`internal/`)

| Balík | Zodpovednosť |
|---|---|
| `capture` | Číta surové rámce zo sieťovej karty (gopacket/pcap), publikuje `core.RawFrame`. Aj analýza nahraného `.pcap`/`.pcapng` súboru (`AnalyzeFile`, cez `pcapgo` — bez Npcapu). Podporuje reštart (Stop/Start) pre admin ovládanie. |
| `ipfix` | Alternatívny zdroj dát k `capture` — UDP listener prijímajúci IPFIX (RFC 7011) exporty, vlastný template-based dekóder. Používa sa namiesto `capture`, keď `capture.mode: ipfix`. |
| `parser` | Dekóduje rámec na `core.Packet` (Ethernet/VLAN, IPv4/IPv6, TCP/UDP, ARP) |
| `asset` | Objavuje zariadenia v sieti (podľa MAC/IP), bez aktívneho skenovania. Rozhoduje o `Confirmed` stave (pozri sekciu 3). |
| `hostname` | Pasívne zisťovanie hostname z mDNS a DHCP prevádzky (sieť bez DNS servera nemá inú možnosť) — obohacuje `asset` záznamy |
| `oui` | Offline lookup výrobcu z MAC adresy (malý zabudovaný zoznam + voliteľný plný IEEE CSV register) |
| `flow` | Sleduje obojsmerné konverzácie (toky) medzi dvojicami zariadení |
| `ics` | Dekóduje Modbus/TCP a S7comm z TCP payloadu na normalizovaný `ics.Message` |
| `store` | Nozomi-štýl uloženie OT premenných (register/DB adresa → posledná hodnota, zmeny, počítadlá) |
| `detect` | Anomaly/rule detekcia: ARP spoofing, baseline odchýlky, kritické ICS operácie, nové zariadenia po baseline → `Alert` |
| `persist` | Perzistencia stavu do `bbolt` súboru, periodický flush, retention pruning (pozastavené kým je capture zastavený) |
| `topology` | Kombinuje asset/flow/tag dáta do node+edge grafu pre vizualizáciu |
| `api` | REST API (gin) vystavujúce stav všetkých enginov + servuje dashboard (`web/`) |
| `debug` | Plaintext výpis paketov a ICS správ do stdout (sanity check) — **default vypnuté**, zapína sa cez `debug.enabled` |
| `export` | Voliteľné (`export.enabled`) — presmeruje každý alert (JSON, cez HTTPS) na externý server, hneď ako vznikne. Pri zapnutí najprv jednorazovo pošle všetky existujúce alerty (backfill), potom priebežne posiela nové. Rovnakým kanálom (rozlíšené `kind` poľom) posiela aj audit záznamy, ak je `audit.enabled` zapnuté. |
| `audit` | Voliteľné (`audit.enabled`) — trvalý záznam "kto čo urobil" cez API (admin akcie, review alertov, zlyhané prihlásenia) do samostatného rotovaného súboru, oddelene od bežného aplikačného logu. Pozri sekciu "Audit log" nižšie. |
| `config` | Načítanie a validácia `config.yaml` (viper) |
| `logger` | Globálny štruktúrovaný logger (zap, JSON na stderr) |
| `core` | Zdieľané typy: `EventBus`, `Event`, `Packet`, `RawFrame` |
| `app` | Zapojenie všetkých enginov dokopy, štart/shutdown |

---

## 3. Dátový model — ako sa čo ukladá

### Assets (`internal/asset`)

Jeden riadok na zariadenie, kľúčovaný podľa MAC adresy. `IP` sa
aktualizuje pri každom videní (DHCP renewal), **s výnimkou** IP
adresy overenej cez ARP — tá je raz potvrdená trvalá a nedá sa
prepísať mimosieťovou (routovanou) prevádzkou cez tú istú MAC (typicky
gateway) — bez tejto ochrany by napr. ping na verejnú IP dočasne
"preklopil" IP adresu brány na tú vzdialenú adresu. Broadcast/multicast
MAC adresy sa ignorujú (nie sú fyzické zariadenia).

**`Confirmed`** — `true` pre každé zariadenie objavené počas alebo
pred baseline learningom. Po skončení learningu (`detect` engine
publikuje snapshot naučených MAC adries) každé **nové** zariadenie
dostane `Confirmed: false`, vyvolá `Alert` typu `new_asset`, a v
dashboarde sa zobrazí červeno na Topology tabe + s tlačidlom Confirm
na Assets tabe, kým ho operátor manuálne nepotvrdí (`POST
/assets/:mac/confirm`).

**`Score`** — číselné riziko/kritickosť zariadenia, default `1`
(bežná stanica). Priraďuje sa podľa **aktuálnej IP adresy** zo
zoznamu `deception.stations` v configu — nie je to trvalý atribút
MAC adresy, prepočítava sa pri každej aktualizácii IP (ak sa
zariadenie presunie na inú IP, napr. DHCP obnovou, skóre sa prepočíta
nanovo podľa novej IP; ak už nezodpovedá žiadnej nakonfigurovanej
stanici, vráti sa na `1`). Zariadenie so `Score >=
deception.honeypotthreshold` (default `100`) sa považuje za
**honeypot** — zámerne nasadenú návnadu — čo spúšťa samostatnú
detekčnú logiku, pozri sekciu "Deception/honeypot" nižšie.

Prepočítava sa aj pri **reštarte appky** — `Restore()` (načítanie z
`otlens.sqlite`) prepočíta `Score` pre každý obnovený asset podľa
**aktuálneho** configu, nie podľa toho, čo bolo uložené predtým. Ak
teda medzi reštartmi zmeníš `deception.stations`, zmena sa prejaví
okamžite pri štarte pre všetky doteraz známe zariadenia — nemusíš
čakať, kým appka dané zariadenie znova uvidí naživo.

### Deception / honeypot stanice (`internal/detect/honeypot.go`)

Honeypot je návnada, ktorá **nemá žiadny legitímny dôvod** iniciovať
alebo prijímať komunikáciu — na rozdiel od baseline learningu (kde
nová komunikácia môže byť falošný poplach, len doteraz nevidená
legitímna aktivita), akákoľvek prevádzka dotýkajúca sa honeypotu je
**vnútorne podozrivá**. Toto dáva veľmi nízku mieru falošných
poplachov v porovnaní s ostatnými detekčnými pravidlami.

Nastavenie v `config.yaml`:

```yaml
deception:
  honeypotthreshold: 100
  stations:
    - ip: "192.168.1.99"
      score: 100
```

Sleduje sa **smer** komunikácie voči nakonfigurovanej IP, s dvoma
odlišnými nálezmi:

- **Niekto sa pripája NA honeypot** (`honeypot_probed`, severity
  `medium`) — presne to, na čo honeypot slúži (zachytáva
  recon/skenovanie). Hodnotný signál ("niekto skenuje sieť"), ale nie
  kritický.
- **Honeypot iniciuje odchádzajúcu komunikáciu** (`honeypot_lateral_movement`,
  severity `critical`) — toto by sa **nikdy** nemalo stať zo stanice,
  ktorá existuje čisto ako návnada. Znamená to, že honeypot bol
  skompromitovaný a útočník sa cez neho šíri ďalej na iné zariadenia
  (lateral movement).

Oba nálezy sú dedupikované podľa dvojice (smer, zdroj, cieľ) — rovnaká
opakovaná komunikácia len aktualizuje `Count`/`LastSeen` na existujúcom
alerte, nevytvára nový pri každom pakete.

**Technický detail dôležitý pre topológiu:** keďže `flow.Flow`
zlučuje **obe** strany konverzácie do jedného záznamu (pozri nižšie),
jeho `SrcIP`/`DstIP` odrážajú len to, ktorý paket prišiel **prvý** v
histórii danej dvojice — nie kto skutočne inicioval konkrétny smer.
Preto `flow.Engine` sleduje `HoneypotInitiated` **per-paket**, priamo
pri každej aktualizácii flow záznamu (nie odvodením spätne z
zamrznutého `SrcIP`), aby červené zvýraznenie hrany v Topology tabe
(pozri sekciu 7) korektne sedelo s `honeypot_lateral_movement`
alertom aj vtedy, keď honeypot iniciuje komunikáciu smerom, ktorý
nebol prvým videným paketom pre danú dvojicu.

### Správa pravidiel (`internal/detect/rules.go`) — Rules tab

Rules tab zobrazuje **všetkých 7 vstavaných detekčných pravidiel** (ARP spoofing, new_communication, ICS critical operation, new_asset, value_out_of_range, honeypot_probed, honeypot_lateral_movement) plus ľubovoľný počet **vlastných pravidiel**, ktoré si operátor vytvorí sám.

**Štatistiky (počet zásahov, posledný zásah, posledná stanica) sa neukladajú samostatne** — počítajú sa **za behu** agregáciou existujúcich `Alert` záznamov podľa ich `Type` poľa (`Count`/`LastSeen`/`IP` tam už boli, presne na toto určené). Žiadny nový mechanizmus sledovania štatistík, len zoskupovací prechod cez to, čo už existuje.

**On/off prepínač** — funguje pre **oba** typy pravidiel rovnako. Pre vstavané pravidlá je to jednoduchý guard na začiatku príslušnej `handle*` funkcie (alebo len okolo samotného vyvolania alertu — pozri nižšie, kde presne kvôli baseline learningu). Vypnuté pravidlo jednoducho nič nevyhodnocuje ani nevyvoláva.

**Dôležitý detail o zamykaní** — `handleBaseline()` (new_communication) drží `e.mutex.Lock()` počas **celej** svojej dĺžky (kvôli priebežnému baseline learning trackingu, ktorý musí bežať bez ohľadu na to, či je alertovanie zapnuté). Kontrola "je pravidlo zapnuté" preto **nemôže** ísť cez verejnú `isRuleEnabled()` (tá by sa pokúsila znova zamknúť ten istý mutex → deadlock) — existuje samostatná `isRuleEnabledLocked()` bez vlastného zamykania, určená presne pre volanie zvnútra už zamknutej sekcie.

**Vlastné pravidlá** — jednoduchý, ale univerzálne použiteľný typ: "ak sa objaví komunikácia, kde pole **X** = hodnota **Y**":

| Field (select box) | Čo porovnáva |
|---|---|
| `src_ip` | Zdrojová IP paketu |
| `dst_ip` | Cieľová IP paketu |
| `either_ip` | Zdrojová **alebo** cieľová IP |
| `protocol` | L4 protokol (`TCP`/`UDP`) |
| `port` | Zdrojový **alebo** cieľový port |

Vyhodnocuje sa **per-paket**, presne rovnaký vzor dispatchu ako každé vstavané pravidlo (`core.EventPacketParsed`). Zásah sa deduplikuje podľa (ID pravidla, zdroj, cieľ) — opakovaná komunikácia na tej istej dvojici len aktualizuje `Count`/`LastSeen` na existujúcom alerte.

**Vstavané pravidlá sa nedajú zmazať**, len vypnúť — `DeleteRule()` vráti `false` pre oba prípady ("neexistuje" aj "je to vstavané pravidlo"), keďže z pohľadu API je to rovnaká situácia ("nič sa nezmazalo").

**Perzistencia** — rovnaký vzor ako assets/flows/tags/alerty (`bucketRules`, `RestoreRules`/`GetRuleConfigs`). Po reštarte appky sa navyše obnoví aj počítadlo `customRuleSeq`, aby nové vlastné pravidlo nekolidovalo ID s obnoveným.

**Wipe database zámerne nemaže pravidlá** — sú to nastavenia, ktoré si operátor vedome nakonfiguroval, nie pozorované sieťové dáta. Vymazanie histórie siete by nemalo ticho zmazať vlastné pravidlá ani znova zapnúť predtým vypnuté vstavané pravidlo.

**API:** `GET /rules`, `POST /rules` (vytvorenie vlastného pravidla), `POST /rules/:id/toggle`, `DELETE /rules/:id` (len vlastné). Všetky štyri akcie sa zaznamenávajú do audit logu (`rule.create`/`rule.toggle`/`rule.delete`).

### Zraniteľnosti podľa výrobcu (`internal/vuln`) — čisto offline

Klik na riadok v Assets tabe otvorí popup so známymi zraniteľnosťami pre **výrobcu** daného zariadenia (rozpoznaného cez OUI/MAC lookup — pozri nižšie).

**Zámerne a výhradne offline — žiadne živé sieťové volanie, nikdy.** OT siete bývajú bežne air-gapped od internetu práve z bezpečnostných dôvodov — to je štandardná, očakávaná prax, nie okrajový prípad, ktorý treba obchádzať. Appka namiesto toho číta **lokálny súbor** (`vulnerability.datapath` v configu), presne rovnaký princíp ako `oui.csvpath` pre vendor lookup.

**Odkiaľ vziať dáta:** [CISA ICS Advisories](https://www.cisa.gov/news-events/ics-advisories) — verejné, špecificky cielené na ICS/OT výrobcov a produkty (na rozdiel od celého NVD dumpu, ktorý má 240 000+ CVE naprieč všetkým softvérom, väčšinou nesúvisiacim s OT). Konkrétne zdroje:
- [`cisagov/CSAF`](https://github.com/cisagov/CSAF) — CISA ICS advisories v štruktúrovanom CSAF JSON formáte, stiahnuteľné hromadne
- [ICS Advisory Project](https://www.icsadvisoryproject.com/) — komunitný CSV export tých istých dát, jednoduchší na spracovanie

**Formát súboru, ktorý appka očakáva** (`vulnerability.datapath`) — jednoduché ploché CSV, **jeden riadok na CVE** (nie na advisory — jedno advisory môže obsahovať viacero CVE, vtedy viacero riadkov), **bez hlavičky**:

```csv
CVE-2024-1234,Siemens,SIMATIC S7-1200,high,SIMATIC S7-1200 Improper Access Control,2024-04-02,https://www.cisa.gov/news-events/ics-advisories/icsa-24-093-01
```

Stĺpce v poradí: `cve_id,vendor,product,severity,title,published_date,url`. Riadky s menej než 7 stĺpcami sa preskočia (nezhodí to celé načítanie) — dá sa teda pripraviť aj ručne/poloautomaticky bez obavy, že jeden pokazený riadok zahodí všetko ostatné.

**Operačný postup (rovnaký, ako bežne funguje aktualizácia antivírusových signatúr v air-gapped OT prostrediach):**
1. Na **inom stroji s internetom** (nie v OT sieti) stiahni/skonvertuj aktuálne CISA ICS advisories do vyššie uvedeného CSV formátu
2. Prenes súbor do OT siete **manuálne** (USB, alebo iný schválený spôsob prenosu dát cez air-gap)
3. Ulož ako `vulnerability.datapath` (default `ics_advisories.csv`, vedľa appky)
4. Periodicky (napr. mesačne) opakuj — appka načíta súbor **len pri štarte appky**, nie priebežne za behu

**Dôležité poctivé obmedzenie — párovanie je len podľa mena výrobcu, nie presného modelu:** appka nemá spôsob, ako pasívne zistiť presný model/firmvér zariadenia (žiadny aktívny fingerprinting). `Lookup()` teda nájde **všetky** zhody podľa `vendor` poľa (case-insensitive, presná zhoda reťazca — nie substring, normalizáciu mena výrobcu treba spraviť už pri príprave CSV) — to znamená, že môže zobraziť CVE, ktoré sa v skutočnosti týkajú **iného** produktu toho istého výrobcu, nesúvisiaceho s konkrétnym zachyteným zariadením. `Product` stĺpec sa zobrazuje len ako **kontext pre človeka** (aby vedel sám posúdiť relevanciu), nikdy sa nepoužíva ako filter.

**API endpoint:** `GET /assets/:mac/vulnerabilities` → `{vendor, advisories: [...], enabled}` — `enabled` rozlišuje "funkcia vypnutá v configu" od "zapnutá, ale pre tohto výrobcu nič v snapshote nie je".

### Rozšírenie OUI (vendor) databázy

Mechanizmus na toto **už existuje**, netreba meniť kód — `internal/oui.Lookup()` skúša najprv voliteľne nahraný CSV (`oui.csvpath`), až potom padá na malú vstavanú tabuľku (177 bežných záznamov). Na plné pokrytie (vrátane menej bežných OT/ICS výrobcov) stačí nastaviť:

```yaml
oui:
  csvpath: "oui.csv"   # stiahnutý z https://standards-oui.ieee.org/oui/oui.csv
```

Súbor je **verejný, zadarmo, bez registrácie** priamo od IEEE — rovnaký princíp ako u vyššie: stiahni na stroji s internetom, prenes manuálne do air-gapped siete.

### Flows (`internal/flow`)

Jeden riadok na **obojsmernú** konverzáciu — paket A→B aj B→A padne
do rovnakého záznamu (kľúč je normalizovaný podľa `protocol|ip:port
(zoradené)`). Toto je najväčšie riziko rastu disku, keďže každé nové
klientske spojenie má nový efemérny port. V `ipfix` móde sa flow
záznamy aktualizujú priamo z exportovaných delta-počítadiel
(`ApplyExternalDelta`), nie paket-po-pakete.

### OT Tags (`internal/store`) — Nozomi-štýl

Namiesto logovania **každého** pollu (Modbus/S7 poll môže bežať každých
100ms) sa ukladá **jeden riadok na premennú** (register/DB adresa),
ktorý sa pri každom pollu len aktualizuje:

- `LastValue` — aktuálna hodnota
- `PreviousValue` + `LastChangeAt` — hodnota pred poslednou zmenou a kedy sa to stalo
- `PollCount` — koľkokrát bola premenná čítaná/zapisovaná
- `ChangeCount` — koľkokrát sa hodnota reálne zmenila

Bežný polling teda stojí O(1) storage (update countera na existujúcom
riadku). Rastú len:

- **`ValueChange`** — append-only záznam, zapisuje sa **len** pri reálnej zmene hodnoty
- **`ControlEvent`** — append-only záznam pre write operácie a
  bezpečnostne relevantné control funkcie (S7 PLCStop/PLCControl) —
  tieto sa **nikdy nededupujú**, každý výskyt je samostatná udalosť

Kompletnú históriu jedného tagu (obe vyššie) je možné pozrieť
priamo v dashboarde — klik na riadok v OT Tags tabe otvorí popup s
históriou (pozri sekciu 7).

Modbus function kódy sa rozpoznávajú všetky (1-23, 43 podľa Modbus
Application Protocol V1.1b3), no detailné dáta (adresa, počet,
**skutočná čítaná/zapisovaná hodnota**) sa parsujú len pre 1-6, 15-16,
a 22 (MaskWriteRegister — write operácia cez AND/OR masky). Pri
viacnásobných čítaniach/zápisoch (quantity > 1) sa hodnoty **rozložia
na jednotlivé adresy** — každý register/coil v rozsahu dostane
vlastný Tag riadok s jednou skalárnou hodnotou (`store.Engine.handle`
→ `expandAddressRange`), namiesto toho, aby sa celý blok hodnôt
natlačil do jedného Tagu na štartovaciu adresu. Toto je zámerné a
dôležité pre presnosť `ChangeCount`/histórie zmien — bez toho by
akákoľvek zmena čo i len jedného bitu v bloku vyzerala ako "zmena
celého bloku" pri každom polle. WriteSingleCoil (fc 5) sa dekóduje ako
`bool` (`0xFF00`=ON/`0x0000`=OFF podľa špecifikácie), nie ako surové
číslo — konzistentne s tým, ako sa coily zobrazujú všade inde
(ReadCoils, WriteMultipleCoils). Ostatné kódy sa zobrazia menom, ale
bez detailov.

### Alerty (`internal/detect`)

Rovnaký dedup princíp — jeden `Alert` na unikátny nález (napr.
konkrétny pár IP↔MAC pri ARP spoofingu), opakované výskyty len
aktualizujú `Count`/`LastSeen`. Alert má trojstavový `Status`
namiesto jednoduchého vybavené/nevybavené:

- **`new`** — default, ešte neskontrolované
- **`approved`** — operátor skontroloval a akceptoval ako
  očakávané/neškodné (napr. legitímna údržba, ktorá len nebola
  videná počas baseline learningu)
- **`confirmed`** — operátor skontroloval a **potvrdil ako reálny
  problém**

Typy alertov: `arp_spoof`, `new_communication` (baseline odchýlka),
`ics_critical_operation` (napr. S7 PLCStop), `new_asset` (zariadenie
po baseline learningu, pozri vyššie), `value_out_of_range` (hodnota
OT premennej mimo naučeného rozsahu, pozri nižšie),
`honeypot_probed`/`honeypot_lateral_movement` (komunikácia s/z
deception stanice, pozri vyššie).

**Rozsah hodnôt OT premenných (`Tag.MinValue`/`MaxValue`)** —
paralelný baseline mechanizmus k asset/komunikačnému baseline, ale
pre samotné **hodnoty** registrov: počas baseline learningu si
`store.Engine` pre každú číselnú premennú (registre — nie coily/bity,
kde "min/max" nedáva zmysel) priebežne zaznamenáva najmenšiu a
najväčšiu videnú hodnotu. Po skončení learningu sa tento rozsah
**zamrazí** — každá ďalšia hodnota mimo `[MinValue, MaxValue]` vyvolá
`value_out_of_range` Alert (opakované výskyty aktualizujú
`Count`/`LastSeen` na tom istom alerte, rovnako ako pri ARP/ICS).
Premenná, ktorá sa počas learningu vôbec nevyskytla, nemá naučený
rozsah — touto mechanikou sa teda nikdy neoznačí (na to slúži
`new_asset`/`new_communication`).

**Zámerne nededupované vekom** (Prune sa ich netýka): `baseline`
naučené vzory (`learnedPatterns`, `learnedAssets`) a ARP `knownMAC`
mapa — sú to "toto je už schválené" stavy, nie história; vekové
mazanie by spôsobilo falošné alerty pre zriedkavú, ale legitímnu
prevádzku (napr. mesačný maintenance job).

---

## 4. Perzistencia a diskový priestor

Všetky dáta (assets, flows, tags, alerty + história) žijú primárne v
RAM. `internal/persist` ich periodicky (default 10s) snapshotuje do
**bbolt** súboru (`otlens.sqlite`), a pri štarte ich späť načíta — takže
reštart appky nestratí stav ani nezačína baseline learning odznova.

### Prečo periodicky, nie pri každom pakete

bbolt robí `fsync` pri každej write transakcii — zápis pri každom
pakete by zhltol len pár stoviek paketov/sekundu ako strop
priepustnosti. Keďže store engine už agresívne dedupuje v pamäti
(jeden riadok na premennú, nie na packet), snapshot každých pár
sekúnd je lacný.

### Retention (proti zaplneniu disku)

`persist.retention` (default 7 dní) — záznamy staršie ako toto okno
(podľa `LastSeen`/`Timestamp`) sa mažú **z pamäte aj z disku** pri
každom flushi. Každý flush zároveň **presne zrkadlí** pamäť na disk
(`syncKeyed`) — takže pruning v pamäti sa reálne prejaví aj
zmenšením súboru, nie len zastavením ďalšieho rastu.

**Dôležité:** manuálne analyzovaný `.pcap` súbor (pozri sekciu 7)
nesie **pôvodné historické timestampy zo súboru**, nie aktuálny čas
— naivné vekové pruning by taký (staršie než retention okno) súbor
zmazalo hneď pri najbližšom flushi. Preto každý asset/flow/tag
vytvorený manuálnou analýzou dostane príznak `FromAnalysis`, ktorý ho
**natrvalo** vyníma z vekového pruningu — bez ohľadu na to, či
capture práve beží alebo nie. Príznak sa zruší (záznam sa vráti k
normálnemu vekovému pruningu) automaticky pri prvom **živom**
potvrdení toho istého zariadenia/flow/tagu (napr. to isté zariadenie
sa znova objaví v živej prevádzke) — len analýza samotná ho už späť
nenastaví.

### Manuálne vymazanie databázy

Admin tab v dashboarde má tlačidlo na okamžité vymazanie **všetkých**
assets/flows/OT tags/alertov naraz (`POST /admin/wipe`, vrátane tých
s `FromAnalysis`), s okamžitým flushom na disk. Vyžaduje zastavený
capture. Baseline learning stav a ARP `knownMAC` mapa sa **nemažú**
— inak by sa baseline musel učiť odznova a mohli by sa spusti
falošné ARP alerty pre už známe mapovania.

---

## 5. REST API

| Endpoint | Metóda | Popis |
|---|---|---|
| `/ui` | GET | Dashboard (statické súbory, pozri sekciu 7) |
| `/assets` | GET | Objavené zariadenia, obohatené o IT/OT klasifikáciu, vendor, hostname |
| `/assets/:mac` | DELETE | Manuálne odstránenie jedného assetu |
| `/assets/:mac/confirm` | POST | Potvrdenie zariadenia označeného ako nové/nepotvrdené |
| `/assets/:mac/vulnerabilities` | GET | Známe CVE pre výrobcu zariadenia — čisto offline, pozri sekciu 3 |
| `/flows` | GET | Sledované sieťové konverzácie |
| `/topology` | GET | Kombinovaný node+edge graf pre vizualizáciu |
| `/tags` | GET | OT premenné (registre) a ich aktuálne hodnoty |
| `/tags/changes` | GET | História zmien hodnôt (voliteľné `?key=...` na filter podľa jedného tagu) |
| `/tags/events` | GET | História write/control operácií (rovnaký `?key=...` filter) |
| `/alerts` | GET | Detegované anomálie |
| `/alerts/:id/approve` | POST | Označiť alert ako skontrolovaný a akceptovaný |
| `/alerts/:id/confirm` | POST | Označiť alert ako skontrolovaný a potvrdený ako reálny problém |
| `/rules` | GET | Zoznam pravidiel (vstavané + vlastné) so štatistikami — pozri sekciu 3 |
| `/rules` | POST | Vytvorenie vlastného pravidla |
| `/rules/:id/toggle` | POST | Zapnutie/vypnutie pravidla (vstavané aj vlastné) |
| `/rules/:id` | DELETE | Zmazanie vlastného pravidla (vstavané sa nedajú zmazať) |
| `/baseline` | GET | Stav baseline learningu (mode, progress) |
| `/health` | GET | Liveness check |
| `/admin/capture/status` | GET | Aktuálny capture mód + či beží |
| `/admin/capture/stop` | POST | Zastaviť aktívny zdroj dát (pcap aj ipfix) |
| `/admin/capture/start` | POST | Znova spustiť zdroj dát (pcap aj ipfix) |
| `/admin/capture/analyze` | POST | Analyzovať nahraný `.pcap`/`.pcapng` súbor (multipart upload, len pcap mód, capture musí byť zastavený) |
| `/admin/wipe` | POST | Vymazať všetky assets/flows/OT tags/alerty (capture musí byť zastavený) |

CORS je defaultne **vypnutý** (`api.corsorigin: ""`) — žiadny
`Access-Control-Allow-Origin` header, takže fungujú len same-origin
requesty (presne to, čo potrebuje zabudovaný dashboard, servovaný z
toho istého procesu pod `/ui`). Nastav na konkrétny origin, len ak
niečo iné naozaj potrebuje cross-origin prístup — vyhni sa `"*"` mimo
lokálneho vývoja, obzvlášť ak `api.username`/`password` nie sú
nastavené.

**Autentifikácia** je voliteľná — HTTP Basic Auth cez
`api.username`/`api.password` (oboje musia byť nastavené naraz, inak
appka pri štarte zlyhá s jasnou chybou). Chráni všetko okrem
`/health`. Heslo môžeš nastaviť aj cez `OTLENS_API_PASSWORD`
environment premennú namiesto plaintext v `config.yaml` (ľubovoľné
nastavenie sa dá takto prepísať — `OTLENS_<SEKCIA>_<POLE>`). Defaultne
vypnutá — appka teda beží bez prihlásenia, kým to explicitne
nezapneš. Vhodné len pre nasadenie v už dôveryhodnej sieti.

TLS je voliteľné (`api.tls.enabled`) — self-signed certifikát sa
vygeneruje automaticky, ak žiadny neexistuje na nakonfigurovaných
cestách.

### Audit log (`internal/audit`)

Voliteľný (`audit.enabled: false` default), trvalý záznam **kto čo
urobil** — oddelený od bežného aplikačného logu (`logging.*`), ktorý
je vysokoobjemový prevádzkový šum. Audit log je zámerne
nízkoobjemový a vysoko dôležitý — jeden riadok na skutočnú akciu.

**Čo sa zaznamenáva** (11 stavo-meniacich API akcií + zlyhané prihlásenia):

| Akcia | Kedy |
|---|---|
| `asset.delete` | `DELETE /assets/:mac` |
| `asset.confirm` | `POST /assets/:mac/confirm` |
| `alert.approve` | `POST /alerts/:id/approve` |
| `alert.confirm` | `POST /alerts/:id/confirm` |
| `admin.capture.stop` | `POST /admin/capture/stop` |
| `admin.capture.start` | `POST /admin/capture/start` |
| `admin.capture.analyze` | `POST /admin/capture/analyze` (s názvom súboru) |
| `admin.wipe` | `POST /admin/wipe` |
| `rule.create` | `POST /rules` |
| `rule.toggle` | `POST /rules/:id/toggle` |
| `rule.delete` | `DELETE /rules/:id` |
| `auth.failed` | Neúspešný pokus o HTTP Basic Auth (ak je `api.username`/`password` zapnuté) |

**Čo sa zámerne NEzaznamenáva:** bežné GET requesty (`/assets`,
`/flows`, `/topology`...). Dashboard robí ~6 requestov každých 5
sekúnd — logovanie *čítania* by vygenerovalo desaťtisíce riadkov
denne bez hodnoty. Audit log sleduje "kto čo zmenil", nie "kto sa
pozeral".

**Formát:** JSON Lines (jeden JSON objekt na riadok) — `timestamp`,
`action`, `source_ip`, `user`, `success`, a `details` (kontext
špecifický pre danú akciu, napr. `mac` alebo `filename`).

**Reálne obmedzenie, ktoré treba poznať:** dnešný HTTP Basic Auth má
**jedno zdieľané** meno/heslo pre všetkých, nie účty per-osoba.
Audit log teda vie zaznamenať *"niekto s platnými prihlasovacími
údajmi z IP X"*, ale nie identitu konkrétnej osoby. Pole `user` je
navrhnuté tak, aby v budúcnosti (ak by appka dostala skutočný
per-osobový login systém) nebolo treba meniť tvar audit záznamu —
len to, ako sa toto pole napĺňa.

**Rotácia** — zdieľa `logging.rotation` nastavenia (veľkostná
rotácia, počet zálohovaných súborov, vekové mazanie, voliteľná gzip
kompresia) s bežným aplikačným logom — vlastná malá implementácia
(`internal/logger/rotate.go`), nie externá závislosť, keďže
lumberjack balík nebolo možné v tomto prostredí stiahnuť. Správanie
je rovnaké (veľkostná rotácia + počet záloh + vekové mazanie +
gzip); ak by bolo niekedy treba prejsť na `lumberjack`, je to
priama náhrada — obe implementujú len `io.Writer`.

**Export** — ak je zapnutý `export.enabled`, audit záznamy sa
posielajú na **rovnaký** server ako alerty (rovnaké `export.url`,
rovnaké TLS nastavenia), len rozlíšené `kind` poľom v JSON payloade
(`"alert"` vs `"audit"`) — netreba samostatnú URL/TLS konfiguráciu
pre audit.

---

## 6. Konfigurácia (`configs/config.yaml`)

Všetky nastavenia, ktoré appka potrebuje, sú v tomto jedinom súbore.
Nič podstatné nie je natvrdo zapísané v kóde. Sekcie:

```yaml
app:
  name: OTLens
  version: 0.1.0

debug:
  enabled: false          # raw stdout dump kazdeho paketu - len na ladenie

export:
  enabled: false                              # posielat alerty na externy server?
  url: "https://siem.example.internal/..."     # HTTPS endpoint (POST JSON)
  tls:
    insecureskipverify: false                  # true len pre self-signed test server
    cacertfile: ""                              # volitelna dovera vlastnej CA
  timeout: 10s

capture:
  mode: pcap              # "pcap" alebo "ipfix" - pozri sekciu 1
  interface: \Device\NPF_{GUID}
  snaplen: 1600
  promiscuous: true
  bpffilter: "ip or arp"
  ipfix:
    listenaddr: "0.0.0.0:4739"   # len pri mode: ipfix

ics:
  modbusport: 502          # 0 = default (502)
  s7port: 102               # 0 = default (102)

baseline:
  enabled: true              # false = preskoci learning, ide rovno do monitoring modu
  learningduration: 10m     # ako dlho sa uci "normalnu" komunikaciu/zariadenia

deception:
  honeypotthreshold: 100     # Score >= tato hodnota = honeypot
  stations: []
    # - ip: "192.168.1.99"
    #   score: 100

detect:
  arpconfirmthreshold: 3    # kolko po sebe iducich konfliktov pred potvrdenim ARP zmeny

store:
  maxvaluechanges: 1000     # count-based safety cap (navrch time-based retention)
  maxcontrolevents: 1000

persist:
  path: otlens.sqlite
  flushinterval: 10s
  retention: 168h            # 7 dni; "0" = navzdy. Pozastavene kym je capture stopnuty.

api:
  host: 0.0.0.0
  port: 8080
  mode: debug                # "debug" alebo "release"
  corsorigin: ""             # "" = ziadny CORS header (len same-origin)
  username: ""               # oboje prazdne = bez autentifikacie
  password: ""               # alebo OTLENS_API_PASSWORD env premenna
  tls:
    enabled: false
    certfile: otlens.crt      # auto-generuje sa self-signed ak chyba
    keyfile: otlens.key
    minversion: "1.2"
    ciphersuites: []

oui:
  csvpath: ""                # volitelny plny IEEE OUI register (CSV)

vulnerability:
  enabled: false             # ciste offline, ziadne zive volania - pozri sekciu 3
  datapath: ics_advisories.csv

logging:
  level: debug
  output:
    - stderr
    # - otlens.log
  rotation:
    enabled: false            # zdielane aj s audit logom nizsie
    maxsizemb: 100
    maxbackups: 10
    maxagedays: 90
    compress: true

audit:
  enabled: false
  path: audit.log            # rotovany podla logging.rotation vyssie
```

### Bežná pasca: spätné lomky v `capture.interface`

Plain (needotknutý) YAML scalar neescapuje spätné lomky — napíš
**jednu** lomku (`\Device\NPF_{GUID}`), nie dve (`\\Device\\NPF_{GUID}`).
Ak to aj tak zadáš zdvojene, appka to sama rozpozná a opraví
(`collapseBackslashes` v `capture.go`), ale správne je to hneď
napísať jednou lomkou.

---

## 7. Webový dashboard (`web/`)

Vanilla HTML/CSS/JS (žiadny build proces, žiadny Node/npm) — appka
si ho servuje sama cez gin (`/ui`). Vizuálny štýl: control room /
engineering blueprint (tmavé HMI pozadie, phosphor-teal pre OT,
amber/červená pre varovania).

| Tab | Obsah |
|---|---|
| **Topology** | Node+edge graf zariadení a ich komunikácie (vis-network, `forceAtlas2Based` fyzika). Farby vysvetlené nižšie. |
| **Assets** | Tabuľka zariadení (IP/MAC/vendor/hostname/OT-IT/protokoly/**Score**/packety), triediteľná podľa stĺpcov, hromadné mazanie cez checkboxy, Confirm tlačidlo pre nové zariadenia, stránkovanie (10/20/50/All riadkov na stránku). **Klik na riadok** otvorí popup so známymi zraniteľnosťami pre výrobcu zariadenia (offline, pozri sekciu 3). |
| **Flows** | Tabuľka konverzácií so stránkovaním (50/100/All riadkov na stránku), triediteľná. |
| **OT Tags** | Tabuľka OT premenných, triediteľná. **Klik na riadok otvorí popup s kompletnou históriou** (zmeny hodnôt + control eventy) danej premennej. |
| **Alerts** | Tabuľka alertov s trojstavovým Approve/Confirm workflow (pozri sekciu 3), hromadné akcie cez checkboxy, triediteľná. |
| **Rules** | Zoznam nakonfigurovaných pravidiel (vstavané + vlastné), on/off prepínač pre každé, počet zásahov/posledný zásah/posledná stanica (agregované z Alert záznamov), "+ Add rule" na vytvorenie vlastného pravidla, Delete pre vlastné pravidlá (vstavané sa dajú len vypnúť). |
| **Admin** | Ovládanie zdroja dát (stop/start, funguje v oboch módoch), upload a analýza `.pcap`/`.pcapng` súboru (len pcap mód), a "Danger zone" s tlačidlom na kompletné vymazanie databázy. |

### Farby v Topology tabe a čo znamenajú

**Uzly (zariadenia):**

| Farba | Kedy | Význam |
|---|---|---|
| 🟣 Fialová (`#a855f7`) | `Score >= deception.honeypotthreshold` | **Honeypot/deception stanica.** Má prednosť pred všetkými ostatnými farbami — je to trvalá, zámerná klasifikácia, nie prechodný stav na revíziu. Ak je zároveň OT zariadenie, pulzuje vo fialových odtieňoch. |
| 🔴 Červená (`#e85d4c`) | `Confirmed === false` | **Nepotvrdené nové zariadenie** — objavené po skončení baseline learningu, nebolo súčasťou naučenej množiny. Zmizne po potvrdení cez Assets tab (tlačidlo Confirm) alebo cez `POST /assets/:mac/confirm`. |
| 🟢 Teal (`#3fbfb0`) | `IsOT === true` (a nie vyššie) | OT/ICS zariadenie — hovorí Modbus alebo S7comm. Jemne pulzuje (farba, nie veľkosť — pulzovanie veľkosti by cez fyzikálnu simuláciu rozhadzovalo susedné uzly). |
| 🔵 Sivo-modrá (`#6b7ea3`) | žiadne z vyššie | Bežné IT zariadenie. |

**Hrany (komunikácia):**

| Farba/štýl | Kedy | Význam |
|---|---|---|
| 🔴 Červená, hrubá, čiarkovaná | `FromHoneypot === true` | **Honeypot iniciuje odchádzajúcu komunikáciu** — návnada, ktorá nemá dôvod niečo kontaktovať, práve niečo kontaktuje. Toto je presne to, na čo vyvolá alert `honeypot_lateral_movement` (pozri sekciu 3) — vizuálne zvýraznené priamo v grafe, nielen v Alerts tabe. |
| 🟢 Teal, hrubšia | `IsOT === true` | Prevádzka cez rozpoznaný OT port (502/Modbus, 102/S7comm) na ktorejkoľvek strane. |
| 🟠 Jantárová, čiarkovaná, **zaoblená** | koncové uzly majú **rôzne** `VLANID` | **Medzi-VLAN komunikácia** — spojenie prekračujúce hranicu VLAN, zvyčajne smerované cez firewall/router. Menšia priorita než honeypot (ak by hrana bola oboje naraz, zobrazí sa červeno). Zámerne **zaoblená** (`smooth: curvedCW`), nie rovná ako ostatné hrany — zariadenie často sedí na zdieľanom konci dvoch hrán naraz (vnútro-VLAN k vlastnému hubu + cross-VLAN inde), a keď VLAN zoskupenie umiestni vzdialený VLAN "za" iný zhluk z pohľadu daného zariadenia, dve rovné čiary z jedného bodu môžu vizuálne vyzerať ako jedna súvislá čiara prechádzajúca cez nesúvisiaci uzol. Zaoblenie túto ilúziu spoľahlivo rozbije — zaoblená čiara sa nikdy nemôže opticky "spojiť" s rovnou tak, ako dve rovné čiary môžu. |
| 🔵 Sivo-modrá, tenšia, priesvitná | ostatné | Bežná IT komunikácia. |

**Poznámka k priorite:** stav honeypotu (fialová) prekrýva stav "nepotvrdené" (červená) aj OT klasifikáciu (teal) — ak je honeypot zároveň novým, nepotvrdeným zariadením, zobrazí sa fialovo, nie červeno. Toto je zámerné: honeypot je trvalá, vedomá klasifikácia z configu, zatiaľ čo "nepotvrdené" je len dočasný stav čakajúci na revíziu operátora.

### Vyhľadávanie a VLAN filter v Topology tabe

**Search bar** nad grafom — hľadá zariadenie podľa **čiastočnej zhody** IP alebo MAC adresy. Nájdené zariadenie sa označí (selection border) a graf sa naň priblíži/vycentruje. Zvýraznenie prežíva ďalšie pravidelné obnovenia dát (5s polling), ale **nezooomuje znova** pri každom obnovení — len drží výber v synchróne s čerstvými dátami, aby to nebolo rušivé, keď si operátor práve pozerá inú časť grafu. Priblíženie/centrovanie sa deje **len** pri samotnej vyhľadávacej akcii.

**VLAN filter** — riadok prepínačov nad grafom, jeden na každý **reálne prítomný** VLAN tag v aktuálnych dátach (žiadny samostatný "zoznam známych VLAN" endpoint — frontend ich zisťuje priamo z `/topology` odpovede). Skrytý úplne, ak je prítomný len jeden (alebo žiadny) VLAN — jediný vždy-zapnutý prepínač by bol zbytočný šum. Všetky VLANy zobrazené **defaultne**; vypnutie prepínača skryje zodpovedajúce zariadenia aj hrany.

Technický detail: hrany sa filtrujú podľa **viditeľnosti oboch koncových uzlov**, nie podľa vlastného `VLANID` hrany — hrana môže v princípe prepájať dve rôzne VLANy (smerovanie medzi VLANmi), takže filtrovanie priamo podľa hrany by mohlo nechať "visiacu" hranu smerujúcu na skrytý uzol.

`VLANID` (802.1Q tag, 0 = netagovaná prevádzka) sa parsuje z paketov už dnes (`internal/parser/ethernet.go`), ale predtým sa nikde ďalej nepoužívalo — teraz sa vlečie cez `asset.Asset.VLANID`/`flow.Flow.VLANID` až po `topology.Node`/`Edge`. Aktualizuje sa **len pri nenulovej hodnote** (rovnaká logika ako `Score`/IP) — netagovaná ("VLAN 0") prevádzka od toho istého zariadenia neprepíše predtým zistený reálny VLAN tag.

**Obmedzenie:** VLAN sa dnes zisťuje len z **live/pcap** zachytávania (802.1Q tag priamo na Ethernet vrstve). V IPFIX móde `Flow.VLANID` zostáva `0` (netagovaná) — IPFIX flow záznamy VLAN informáciu momentálne nepretŕhajú.

**Medzi-VLAN komunikácia** — hrana, ktorej dva koncové uzly majú **rôzne** `VLANID`, sa vykreslí odlišne (jantárová, čiarkovaná — pozri tabuľku farieb vyššie), keďže spojenie prekračujúce VLAN hranicu je zvyčajne smerované cez firewall/router a je to práve typ nálezu, ktorý má zmysel vidieť na prvý pohľad.

**Dôležitá poctivá poznámka k obmedzeniu:** toto porovnáva **surové číslo** VLAN ID. VLAN tag je garantovane unikátny len v rámci **jedného** trunku/broadcast domény, nie globálne — ak by appka niekedy zachytávala prevádzku z viacerých fyzicky odlišných sietí, ktoré náhodou číslujú VLAN rovnako (napr. "VLAN 10" na dvoch different lokalitách), dve zariadenia s rovnakým číslom VLAN sa budú považovať za tú istú VLAN, aj keby v realite išlo o dve nesúvisiace siete. Dáta neobsahujú žiadny samostatný identifikátor lokality/segmentu, ktorý by toto rozlíšil.

### Vizuálne zoskupenie zariadení podľa VLAN v 2D grafe

Zariadenia patriace do rovnakej VLAN sa vizuálne zhlukujú do vlastnej oblasti grafu — bez toho, aby ich pozícia bola natvrdo fixovaná (graf zostáva plne interaktívny, ťahateľný, s normálnou fyzikou).

**Mechanizmus** (`computeVlanAnchors` + `renderGraph`, `web/app.js`): pre každý reálne prítomný VLAN sa vypočíta jeden pevný, **neviditeľný "kotviaci" bod**, rovnomerne rozmiestnený po kružnici (polomer škáluje s počtom VLAN). Ku každému kotviacemu bodu sa pridá skrytý `vis-network` uzol (`hidden: true, physics: false, fixed: {x:true, y:true}`) — vis-network dokumentuje, že skrytý uzol **naďalej plne participuje vo fyzikálnej simulácii**, len sa nevykresľuje. Každé zariadenie danej VLAN dostane krátku, skrytú "pružinovú" hranu smerom k svojmu kotviacemu bodu (`length: 100`) — to je to, čo ho reálne priťahuje do správnej oblasti.

Výsledok: zariadenia v tej istej VLAN sa organicky zhluknú blízko seba (normálne odpudzovanie/väzby medzi nimi stále platia — nič nie je fixované), zatiaľ čo rôzne VLAN zhluky sa navzájom rozostúpia vďaka kombinácii kotviacich pružín a bežného odpudzovania medzi uzlami. Medzi-VLAN hrany (jantárová, čiarkovaná farba — pozri tabuľku vyššie) tak vizuálne **viditeľne prechádzajú medzi zhlukmi**, presne tak, ako by mali.

**Jeden VLAN (alebo žiadny)** — `computeVlanAnchors` vráti prázdnu mapu, mechanizmus sa vôbec nezapojí (nemá zmysel zhlukovať proti jedinému bodu), žiadna zmena správania oproti stavu bez VLAN dát.

**Prečo nie skutočné 3D:** skúšalo sa aj 3D zobrazenie (vrstvy podľa VLAN na osi Z, cez `3d-force-graph`/ThreeJS) — v praxi sa ukázalo menej prehľadné než 2D (oklúzia uzlov/hrán v priestore, náročnejšie myšou ovládateľná kamera, vyššie nároky na GPU) a bolo odstránené v prospech tohto zoskupovacieho mechanizmu v rámci existujúceho 2D grafu.

Polling každých 5 sekúnd. Všetky tabuľky používajú stabilné triedenie
(explicitné, nie poradie z Go mapy — to by sa menilo pri každom
requeste a vyzeralo by to, akoby záznamy "miznú"), vrátane
sekundárneho tie-breakera (podľa unikátneho ID) pre prípad, že sa
viacero záznamov zhoduje v hlavnom triediacom kľúči (napr. rovnaký
`LastSeen` — bežné hneď po dávkovej pcap analýze) — bez neho by sa
poradie medzi takýmito "zviazanými" záznamami stále menilo pri
každom polle, aj keď hlavný kľúč zostal rovnaký.

---

## 8. Známe obmedzenia a odporúčaný ďalší postup

1. **S7comm item-level adresovanie** — čiastočne implementované:
   `ReadVar`/`WriteVar` Job (request) správy s bežnou S7ANY
   adresáciou sa dekódujú na úroveň area/DB/adresa (napr.
   `DB100.48.3`), a `WriteVar` požiadavky nesú aj skutočne zapisovanú
   hodnotu (z DATA sekcie tej istej správy). **Nepokryté:**
   symbolická/optimalizovaná adresácia (S7-1200/1500 môžu použiť iný
   syntax ID), viacpoložkové (multi-item) požiadavky (dekóduje sa len
   prvá položka), a hodnoty pri `ReadVar` — tie sú len v response
   správe, ktorá adresu neopakuje (rovnaké obmedzenie ako pri Modbus
   read response, pozri bod 2). S7comm nemá oficiálnu verejnú
   špecifikáciu (reverse-engineered komunitou — Wireshark, snap7),
   takže presnosť dekódovania hodnôt (najmä konvencia dĺžka-v-bitoch
   vs. dĺžka-v-bajtoch) je best-effort, nie zaručená pre všetky
   transport-size varianty.
2. **Request/response korelácia** — `ics.Message.IsResponse` sa určuje
   heuristicky podľa smeru, nie skutočným trackovaním transaction ID
   naprieč oboma smermi. Toto je realizovateľné (Modbus MBAP hlavička
   nesie 2-bajtové Transaction Identifier, S7comm analogicky PDU
   reference — obe polia sa dnes parsujú, ale zahadzujú). Priradenie
   hodnôt ku konkrétnym adresám pri viacnásobných čítaniach/zápisoch
   **už funguje** aj bez toho (pozri sekciu 3 — `expandAddressRange`
   použije štartovaciu adresu z toho istého requestu/response a
   `quantity`), takže skutočná transaction ID korelácia by teraz
   priniesla hlavne presnejšie `IsResponse` a spoľahlivejšie párovanie
   pri pipelined requestoch (viac requestov naraz pred prijatím
   odpovedí) — nie základnú funkčnosť priradenia adries.
3. **Šifrovanie bbolt súboru na disku** — nie je implementované
   (TLS pre REST API komunikáciu **je** implementované, pozri
   sekciu 5/6 — toto je o dátach na disku, nie o prenose; ani HTTP
   Basic Auth, pozri sekciu 5/6, sa toho netýka — chráni prístup cez
   API, nie dáta ležiace na disku). Keďže je bbolt čisté Go (bez
   CGO), dá sa doplniť cez `crypto/cipher` (AES-GCM) na úrovni
   jednotlivých hodnôt bez ťahania C knižníc (na rozdiel od
   SQLCipher).
4. **IPFIX mód nemá manuálnu pcap analýzu** — Stop/Start a Wipe
   database v Admin tabe fungujú v oboch módoch (`pcap` aj `ipfix`),
   ale nahratie a analýza `.pcap` súboru zostáva len pre `pcap`
   (analyzovať packet capture súbor cez flow-only IPFIX pipeline
   koncepčne nedáva zmysel).
5. **OUI vendor databáza** — zabudovaný zoznam je zámerne malý a
   pokrýva len vysoko-dôveryhodné záznamy (žiadne hádané OT/ICS
   prefixy). Pre plné pokrytie treba doplniť `oui.csvpath` oficiálnym
   IEEE registrom.
6. **ARP-verified IP lock nie je perzistovaný** — po reštarte appky sa
   `arpVerified` stav (pozri sekciu 3) začína odznova; kým sa MAC
   znova neoverí čerstvým ARP paketom, jej IP sa teoreticky môže na
   krátko nesprávne prepísať mimosieťovou prevádzkou (samoopraví sa
   pri najbližšom ARP).
7. **Export alertov nemá retry frontu** — `internal/export` je
   best-effort: ak je externý server dočasne nedostupný, alerty
   raisnuté počas výpadku sa jednoducho nepošlú (zalogujú sa ako
   varovanie), nečakajú si na opätovný pokus. Trvalá retry fronta by
   vyžadovala vlastnú perzistenciu/backpressure — zámerne
   neimplementované, keďže lokálne alerty a ich uloženie tým nie sú
   nijak ovplyvnené.
8. **Žiadny rate limiting** — ani na bežných GET endpointoch, ani na
   `/admin/wipe`/`/admin/capture/analyze` (upload súboru). Basic
   Auth/CORS (pozri sekciu 5/6) chránia pred neautorizovaným
   prístupom, ale nie pred zahltením requestmi od niekoho, kto sa už
   prihlásiť vie. Pri nasadení mimo dôveryhodnej siete stojí za
   zváženie reverse proxy s rate limitingom pred appkou.
9. **Audit log nemá per-osobovú identitu** — `api.username`/
   `password` je jedno zdieľané heslo pre všetkých, takže pole
   `user` v audit zázname vie ukázať len *"niekto s platnými
   údajmi"*, nie konkrétnu osobu. Dátový model (`core.AuditEntry`)
   je navrhnutý tak, aby to neskôr nevyžadovalo zmenu tvaru záznamu
   — len rozšírenie auth vrstvy o skutočné per-osobové účty.
10. **Log rotácia je vlastná implementácia, nie `lumberjack`** —
    v tomto vývojovom prostredí nebolo možné stiahnuť externé Go
    závislosti (žiadny prístup na internet), takže `internal/logger/
    rotate.go` je malá, ručne napísaná náhrada rovnakého správania
    (veľkostná rotácia, počet záloh, vekové mazanie, gzip) len zo
    štandardnej knižnice. Funkčne rovnocenné, menej odskúšané v
    praxi než zavedená knižnica — ak by sa niekedy ukázal problém
    (napr. edge case v súbežnom prístupe k súboru), zváž prechod na
    `lumberjack` (priama náhrada, obe implementujú len `io.Writer`).
11. **Zraniteľnosti sa párujú len podľa mena výrobcu** —
    `internal/vuln` nemá spôsob, ako pasívne zistiť presný
    model/firmvér zariadenia, takže `GET /assets/:mac/vulnerabilities`
    môže zobraziť CVE týkajúce sa **iného** produktu toho istého
    výrobcu. Zámerný, poctivo zdokumentovaný strop presnosti pre
    čisto pasívny nástroj — nie chyba. Súbor s dátami (`vulnerability.
    datapath`) sa navyše načítava **len pri štarte appky**, nie
    priebežne — treba appku reštartovať po nahradení súboru novším
    snapshotom.

---

## 9. História vývoja (kontext pre budúcu prácu)

Projekt vznikal iteratívne, vo veľkých fázach:

1. Packet capture, L2-L4 parser, flow tracking, asset discovery
2. OT/ICS parsing (Modbus, S7comm) + Nozomi-štýl storage (`internal/store`)
3. Detekčná vrstva (ARP spoofing, baseline learning, ICS critical ops)
4. REST API, CORS, `/topology`, bbolt perzistencia + retention
5. Webový dashboard (vanilla JS, vis-network topológia)
6. Hostname discovery (mDNS/DHCP), OUI vendor lookup
7. TLS pre API, konfigurovateľné logovanie
8. IPFIX ako alternatívny zdroj dát (bez potreby Npcap/admin práv)
9. Admin ovládanie: capture stop/start, manuálna pcap analýza
   (pôvodné timestampy zo súboru, nie čas spracovania), kompletné
   vymazanie databázy
10. Baseline-driven "nové zariadenie" detekcia (`Confirmed` workflow,
    červené zvýraznenie v topológii)
11. Trojstavový alert review workflow (new/approved/confirmed),
    stránkovanie a triedenie tabuliek, hromadné akcie
12. Tag history popup, odstránenie nepoužitého kódu (debug prepínač,
    mŕtve API endpointy)
