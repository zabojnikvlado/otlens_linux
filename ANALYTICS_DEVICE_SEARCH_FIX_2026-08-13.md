# OTLens — Analytics device search UX

Date: 2026-08-13

## What changed

The Analytics controls that select a concrete asset are now searchable comboboxes instead of fixed `<select>` lists:

- Communication analysis — Device A
- Communication analysis — Device B
- Asset traffic — Asset

## Display order

Selected assets are displayed consistently as:

`IP address · hostname`

The dropdown keeps IP as the primary field and hostname as the secondary field. Device category and sensor ID are shown as supporting metadata in the suggestion list.

## Search behavior

- IP addresses use prefix matching. Typing `10.1.222.2` shows assets whose address starts with that prefix, such as `10.1.222.20`, `10.1.222.205`, and `10.1.222.230`.
- Hostnames can also be searched (prefix or substring).
- Name, MAC, category and sensor ID remain searchable supporting terms.
- Results are ranked with IP-prefix matches first, then hostname matches, and are naturally sorted by IP.
- At most 60 suggestions are rendered at once; the UI asks the operator to type more characters when additional matches exist.

## Selection behavior

- The selected stable asset identity and sensor are stored separately from the visible `IP · hostname` text.
- If typed text resolves to exactly one asset, Analyze can resolve it without requiring a mouse click.
- Ambiguous text requires choosing one suggestion, preventing a prefix from silently selecting the wrong device.
- Device B can be cleared to preserve the existing `Any peer` behavior.
- Changing the sensor refreshes the available device list and clears a selection that is no longer valid for that sensor.

## Accessibility / keyboard

- Inputs use combobox/listbox ARIA semantics.
- Arrow Up/Down moves through suggestions.
- Enter selects the highlighted/first matching asset.
- Escape closes suggestions.

## Deployment

Web UI / Central only. No sensor change and no database migration are required.

Cache versions:

- `style.css?v=30`
- `app-analytics.js?v=8`
