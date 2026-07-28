# Purdue architecture view and inventory imports

## Topology

The Topology tab remains the live communication graph. Its forceAtlas2 gravity,
stabilisation and animation behaviour are unchanged. Asset-to-asset communication,
honeypot lateral-movement highlighting and inter-VLAN edge highlighting remain
available. Purdue is now an optional node-colour mode rather than a large overlay.

## Purdue

The dedicated Purdue tab uses a layered architecture view for levels 5 through 0.
Unclassified assets are collapsed by default, coverage is shown separately, and
heuristic suggestions can be reviewed and accepted as per-asset overrides.

## Asset-list import

The Devices tab accepts CSV and JSON.

CSV may be headerless (`mac,category,name`) or use a `mac` header.
JSON is an array of objects using `mac`, `category`, and `name` fields.

## Tag-list import

The OT Tags tab accepts CSV and JSON. Imported tags are centrally stored and merged
with live sensor tags by sensor and stable tag key.

CSV may have a header or use this default order:

`device_ip,device_port,protocol,address_space,address,name,operation`

JSON is an array of objects. CamelCase sensor field names and snake_case import
field names are both accepted.
