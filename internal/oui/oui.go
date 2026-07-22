// Package oui identifies a device's manufacturer from its MAC
// address's OUI (Organizationally Unique Identifier — the first 3
// bytes). It ships with a small, deliberately minimal built-in seed
// list covering only entries verified with high confidence
// (virtualization platforms, Raspberry Pi) — NOT a general-purpose
// vendor database, and specifically NOT authoritative for OT/ICS
// vendors (Siemens alone has 21 separately registered OUI blocks,
// Rockwell 14, Schneider Electric 8 — hardcoding a guessed "the"
// prefix per vendor would be actively misleading in a security
// tool).
//
// For real vendor coverage, download the official IEEE registry
// (https://standards-oui.ieee.org/oui/oui.csv — public, no
// authentication needed) and call LoadCSV with its path at startup;
// see config.yaml's oui.csvpath.
package oui

import (
	"encoding/csv"
	"os"
	"strconv"
	"strings"
)

// builtin covers only entries this codebase can be highly confident
// about without the full IEEE registry loaded. Keys are 6 uppercase
// hex characters (no separators).
//
// The virtualization/SBC entries above are a handful of well-known
// prefixes; the block below adds common IT/SOHO networking and PC
// vendors (ASUS, TP-Link, D-Link, Netgear, Ubiquiti, Dell, HP,
// Lenovo) that show up constantly mixed in on real networks
// alongside OT devices. Same bar applies: only prefixes actually
// verified against real registry data, not guessed — each vendor
// has dozens to hundreds of real OUI blocks, so this list will
// still miss many of a given vendor's devices; load the full IEEE
// registry via LoadCSV for complete coverage.
var builtin = map[string]string{
	"000C29": "VMware",
	"005056": "VMware",
	"000569": "VMware",
	"080027": "Oracle VirtualBox",
	"00155D": "Microsoft Hyper-V",
	"00163E": "Xen",
	"525400": "QEMU/KVM (virtual)",
	"B827EB": "Raspberry Pi Foundation",
	"DCA632": "Raspberry Pi Trading Ltd",
	"E45F01": "Raspberry Pi Trading Ltd",

	// ASUS
	"002618": "ASUSTek COMPUTER INC.",
	"049226": "ASUSTek COMPUTER INC.",
	"6045CB": "ASUSTek COMPUTER INC.",
	"10C37B": "ASUSTek COMPUTER INC.",
	"9C5C8E": "ASUSTek COMPUTER INC.",
	"F46D04": "ASUSTek COMPUTER INC.",
	"0015F2": "ASUSTek COMPUTER INC.",
	"001D60": "ASUSTek COMPUTER INC.",
	"000EA6": "ASUSTek COMPUTER INC.",
	"000C6E": "ASUSTek COMPUTER INC.",
	"00E018": "ASUSTek COMPUTER INC.",
	"E03F49": "ASUSTek COMPUTER INC.",
	"54A050": "ASUSTek COMPUTER INC.",
	"88D7F6": "ASUSTek COMPUTER INC.",
	"90E6BA": "ASUSTek COMPUTER INC.",
	"04D9F5": "ASUSTek COMPUTER INC.",
	"1C872C": "ASUSTek COMPUTER INC.",
	"2C56DC": "ASUSTek COMPUTER INC.",
	"38D547": "ASUSTek COMPUTER INC.",
	"50465D": "ASUSTek COMPUTER INC.",
	"704D7B": "ASUSTek COMPUTER INC.",
	"AC220B": "ASUSTek COMPUTER INC.",
	"BCEE7B": "ASUSTek COMPUTER INC.",
	"D850E6": "ASUSTek COMPUTER INC.",
	"F832E4": "ASUSTek COMPUTER INC.",

	// TP-Link
	"68DDB7": "Tp-Link Technologies Co.,Ltd.",
	"14D864": "Tp-Link Technologies Co.,Ltd.",
	"AC84C6": "Tp-Link Technologies Co.,Ltd.",
	"6CB158": "Tp-Link Technologies Co.,Ltd.",
	"34F716": "Tp-Link Technologies Co.,Ltd.",
	"246968": "Tp-Link Technologies Co.,Ltd.",
	"D807B6": "Tp-Link Technologies Co.,Ltd.",
	"646E97": "Tp-Link Technologies Co.,Ltd.",
	"90F652": "Tp-Link Technologies Co.,Ltd.",
	"14CF92": "Tp-Link Technologies Co.,Ltd.",
	"20DCE6": "Tp-Link Technologies Co.,Ltd.",
	"14CC20": "Tp-Link Technologies Co.,Ltd.",
	"808917": "Tp-Link Technologies Co.,Ltd.",
	"C025E9": "Tp-Link Technologies Co.,Ltd.",
	"B0958E": "Tp-Link Technologies Co.,Ltd.",
	"E8DE27": "Tp-Link Technologies Co.,Ltd.",
	"C4E984": "Tp-Link Technologies Co.,Ltd.",
	"54C80F": "Tp-Link Technologies Co.,Ltd.",
	"E4D332": "Tp-Link Technologies Co.,Ltd.",
	"40169F": "Tp-Link Technologies Co.,Ltd.",
	"F4EC38": "Tp-Link Technologies Co.,Ltd.",
	"94D9B3": "Tp-Link Technologies Co.,Ltd.",
	"282CB2": "Tp-Link Technologies Co.,Ltd.",
	"54A703": "Tp-Link Technologies Co.,Ltd.",
	"1C3BF3": "Tp-Link Technologies Co.,Ltd.",
	"5091E3": "Tp-Link Technologies Co.,Ltd.",
	"9C53CD": "Tp-Link Technologies Co.,Ltd.",
	"B0A7B9": "Tp-Link Technologies Co.,Ltd.",
	"D461DA": "Tp-Link Technologies Co.,Ltd.",

	// Intel — extremely common in laptops/desktops/NUCs; omitted
	// entirely before, which is likely why Intel-based devices showed
	// no vendor.
	"E4C767": "Intel Corporate",
	"C0A5E8": "Intel Corporate",
	"906584": "Intel Corporate",
	"28C5D2": "Intel Corporate",
	"102E00": "Intel Corporate",
	"203A43": "Intel Corporate",
	"7C5079": "Intel Corporate",
	"8038FB": "Intel Corporate",
	"AC8247": "Intel Corporate",
	"4C1D96": "Intel Corporate",
	"94E6F7": "Intel Corporate",
	"AC198E": "Intel Corporate",
	"C85EA9": "Intel Corporate",
	"D0ABD5": "Intel Corporate",
	"8CF8C5": "Intel Corporate",
	"A05950": "Intel Corporate",
	"F44637": "Intel Corporate",
	"E884A5": "Intel Corporate",
	"3C9C0F": "Intel Corporate",
	"C43D1A": "Intel Corporate",
	"04E8B9": "Intel Corporate",
	"E02E0B": "Intel Corporate",
	"F4B301": "Intel Corporate",
	"546CEB": "Intel Corporate",
	"009337": "Intel Corporate",
	"58CE2A": "Intel Corporate",
	"6479F0": "Intel Corporate",
	"847B57": "Intel Corporate",
	"D83BBF": "Intel Corporate",
	"14F6D8": "Intel Corporate",
	"3887D5": "Intel Corporate",
	"103D1C": "Intel Corporate",
	"646EE0": "Intel Corporate",
	"0456E5": "Intel Corporate",
	"581CF8": "Intel Corporate",

	// D-Link
	"BC2228": "D-Link International",
	"A0A3F0": "D-Link International",
	"C412F5": "D-Link International",
	"1C5F2B": "D-Link International",
	"B0C554": "D-Link International",
	"CCB255": "D-Link International",
	"28107B": "D-Link International",
	"FC7516": "D-Link International",
	"84C9B2": "D-Link International",
	"C8D3A3": "D-Link International",
	"9094E4": "D-Link International",
	"1CAFF7": "D-Link International",
	"14D64D": "D-Link International",
	"BC0F9A": "D-Link International",
	"1062EB": "D-Link International",
	"74DADA": "D-Link International",
	"0050BA": "D-Link Corporation",
	"00179A": "D-Link Corporation",
	"001CF0": "D-Link Corporation",
	"001E58": "D-Link Corporation",
	"0022B0": "D-Link Corporation",
	"002401": "D-Link Corporation",

	// Netgear
	"405D82": "Netgear",
	"DCEF09": "Netgear",

	// Ubiquiti
	"F09FC2": "Ubiquiti Inc",
	"802AA8": "Ubiquiti Inc",
	"788A20": "Ubiquiti Inc",
	"7483C2": "Ubiquiti Inc",
	"E063DA": "Ubiquiti Inc",
	"245A4C": "Ubiquiti Inc",
	"602232": "Ubiquiti Inc",
	"E43883": "Ubiquiti Inc",

	// Dell
	"D0431E": "Dell Inc.",
	"00C04F": "Dell Inc.",
	"00B0D0": "Dell Inc.",
	"0019B9": "Dell Inc.",
	"001AA0": "Dell Inc.",
	"002564": "Dell Inc.",
	"A4BADB": "Dell Inc.",
	"782BCB": "Dell Inc.",
	"14FEB5": "Dell Inc.",
	"180373": "Dell Inc.",
	"74867A": "Dell Inc.",
	"204747": "Dell Inc.",
	"001C23": "Dell Inc.",
	"D481D7": "Dell Inc.",
	"54BF64": "Dell Inc.",
	"4CD98F": "Dell Inc.",
	"6C2B59": "Dell Inc.",
	"185A58": "Dell Inc.",
	"B44506": "Dell Inc.",
	"E0D848": "Dell Inc.",

	// HP / Hewlett Packard
	"644ED7": "HP Inc.",
	"7C4D8F": "HP Inc.",
	"5C60BA": "HP Inc.",
	"508140": "HP Inc.",
	"F80DAC": "HP Inc.",
	"040E3C": "HP Inc.",
	"9C7BEF": "Hewlett Packard",
	"B499BA": "Hewlett Packard",
	"705A0F": "Hewlett Packard",
	"2C4138": "Hewlett Packard",
	"441EA1": "Hewlett Packard",
	"001CC4": "Hewlett Packard",
	"001E0B": "Hewlett Packard",
	"6C3BE5": "Hewlett Packard",
	"A0B3CC": "Hewlett Packard",
	"784859": "Hewlett Packard",
	"002264": "Hewlett Packard",
	"0025B3": "Hewlett Packard",
	"643150": "Hewlett Packard",
	"001083": "Hewlett Packard",
	"10E7C6": "Hewlett Packard",
	"B8AF67": "Hewlett Packard",
	"80CE62": "Hewlett Packard",

	// Lenovo
	"10C595": "Lenovo",
	"A41194": "Lenovo",
	"48C35A": "Lenovo(Beijing)Co., Ltd.",
}

// loaded holds whatever was brought in via LoadCSV, checked before
// builtin so a full registry (which may itself contain entries also
// present in builtin, potentially with more precise naming) takes
// precedence.
var loaded map[string]string

// LoadCSV reads the official IEEE MA-L registry format (columns:
// Registry,Assignment,Organization Name,Organization Address — see
// the package doc comment for where to get it) and makes its
// entries available to Lookup. Safe to call once at startup; if the
// file doesn't exist or fails to parse, returns an error and leaves
// the built-in seed list as the only source — this is not fatal to
// the rest of OTLens, just reduced vendor identification.
func LoadCSV(path string) error {

	f, err := os.Open(path)

	if err != nil {
		return err
	}

	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1 // tolerate ragged rows rather than failing the whole load

	records, err := reader.ReadAll()

	if err != nil {
		return err
	}

	result := make(map[string]string, len(records))

	for _, row := range records {

		if len(row) < 3 {
			continue
		}

		oui := strings.ToUpper(strings.TrimSpace(row[1]))

		if len(oui) != 6 {
			continue
		}

		result[oui] = strings.TrimSpace(row[2])
	}

	loaded = result

	return nil
}

// Lookup returns a human-readable vendor/description for a MAC
// address. Never returns an error — an unrecognized or malformed
// address just yields "Unknown vendor", since this is a best-effort
// display enrichment, not something anything else depends on.
func Lookup(mac string) string {

	normalized := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	normalized = strings.ReplaceAll(normalized, "-", "")

	if len(normalized) < 6 {
		return "Unknown vendor"
	}

	firstByteHex := normalized[0:2]

	firstByte, err := strconv.ParseUint(firstByteHex, 16, 8)

	if err == nil {

		// The "locally administered" bit (the second-least-significant
		// bit of the first octet) is part of the IEEE 802 addressing
		// standard itself, not vendor data — when set, this address
		// was assigned by software (a VM, container, or a privacy/
		// randomized MAC), not drawn from a manufacturer's OUI block
		// at all, so no vendor lookup would ever be meaningful here
		// regardless of how complete the database is.
		if firstByte&0x02 != 0 {

			// QEMU/KVM's conventional 52:54:00 prefix is technically
			// within the locally-administered range too, but common
			// enough to name specifically rather than just "locally
			// administered" — the builtin/loaded map check below
			// still runs first for it via the OUI key match.
			oui := normalized[0:6]

			if name, ok := loaded[oui]; ok {
				return name
			}

			if name, ok := builtin[oui]; ok {
				return name
			}

			return "Locally administered (VM/container/randomized)"
		}
	}

	oui := normalized[0:6]

	if name, ok := loaded[oui]; ok {
		return name
	}

	if name, ok := builtin[oui]; ok {
		return name
	}

	return "Unknown vendor"
}
