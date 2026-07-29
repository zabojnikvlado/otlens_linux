# Web UI JavaScript module split

The former monolithic `web/central/app.js` has been divided into ordered,
domain-oriented classic-script modules. This keeps the existing global lexical
state and event-handler behavior intact while making individual areas easier to
review and maintain without introducing Node.js, a bundler, or a frontend build
pipeline.

Load order in `index.html`:

1. `datatable.js`
2. `app-core.js` — shared state, API client, live connection and refresh primitives
3. `app-topology.js` — topology and network visualization
4. `app-inventory.js` — assets, devices, vulnerabilities and OT tags
5. `app-detection.js` — alerts, incidents, rules and threat intelligence
6. `app-operations.js` — dashboard, audit, health, data and runtime operations
7. `app-admin.js` — users, roles, settings, navigation and feature bootstrap
8. `app.js` — small bootstrap marker

The six functional modules concatenate byte-for-byte to the previous `app.js`,
so this change is structural rather than behavioral. Script order must remain
stable because the modules intentionally share the same classic-script global
lexical environment.

Only OTLens Central needs to be rebuilt.
