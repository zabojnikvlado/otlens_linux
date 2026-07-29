# UI, PDF and sensor metrics follow-up

- Styled the Topology source-IP and Data Management backup-name inputs with the shared dark form controls.
- Added a downloadable vulnerability CSV template.
- Restored panel spacing for Threat Intelligence Indicators and Observed hits tables.
- PDF plain-text conversion now removes complete style and script blocks before rendering.
- Sensor config loading now reads `capture.tcp_reassembly.enabled` directly from Viper after unmarshal, preventing the nested switch from incorrectly remaining false.
