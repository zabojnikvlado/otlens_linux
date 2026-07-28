# Filter chip sizing fix

Fixed the VLAN filters on the Topology tab and category filters on the Device classification tab.

A generic toolbar rule applied a large `min-width` to every input, including checkboxes inside filter chips. The checkbox therefore expanded the chip border far beyond its text.

The filter chips now:

- use content-sized width,
- never grow as flex items,
- keep checkboxes at 12 x 12 pixels,
- explicitly reset inherited input `min-width` and padding,
- retain wrapping and horizontal scrolling behavior where applicable.
