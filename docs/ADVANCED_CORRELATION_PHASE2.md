# Advanced Correlation Engine — Phase 2 completion

This release replaces the fixed 24-hour/two-type grouping with centrally managed correlation rules.

Each rule supports:

- an independent rolling time window;
- a minimum event count;
- required alert types;
- an optional ordered event sequence;
- severity, score and confidence weights;
- MITRE ATT&CK tactic and technique mappings;
- enable/disable state;
- protected built-in rules and deletable custom rules.

The Incidents UI includes a correlation-rule manager. Incident records retain the rule name and MITRE context that caused the correlation, and the workbench displays that reasoning next to the event timeline.

Schema migration version: 5.
