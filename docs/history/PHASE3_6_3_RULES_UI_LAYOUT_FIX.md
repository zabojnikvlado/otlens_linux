# Phase 3.6.3 - Rules UI layout fix

This maintenance release fixes two presentation problems in the Central Rules tab.

## Rule editor modal

The modal backdrop and dialog card previously shared the `.modal` selector. The
backdrop therefore inherited a 640 px maximum width and was anchored to the left
side of the viewport. The backdrop is now always full-screen, while `.modal-card`
is centered independently and constrained to the available viewport height.

The editor remains usable on small displays by switching to a 10 px viewport
margin and a single-column condition layout.

## Rule action switch

The Enable/Disable action previously reused the `.rule-toggle` class intended for
a compact form switch. The text button consequently inherited a 36 x 20 px size
and its label overflowed into the built-in marker.

The Rules table now uses a dedicated `rule-state-toggle` switch with accessible
`aria-pressed`, label and title attributes. Custom-rule Edit and Delete actions
remain separate buttons.
