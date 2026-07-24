# OTLens Phase 3.6.6 – Central PCAP Analysis and Import

## Overview

Central now contains an **Analysis** tab for importing `.pcap` and `.pcapng` captures into a selected Linux sensor. The file is stored temporarily by Central, claimed by the selected sensor over the authenticated Sensor API, and replayed through the same packet, asset, flow, Modbus/TCP, Siemens S7comm, OT tag and detection pipeline used by live capture.

This version implements **analysis with import**. Results become part of the selected sensor's normal state and are included in its next telemetry snapshot. An isolated preview sandbox is not implemented in this phase.

## Central configuration

```yaml
analysis:
  enabled: true
  upload_directory: "C:\\ProgramData\\OTLens\\pcap-uploads"
  max_upload_size_mb: 2048
  job_timeout: 2h
  retain_pcap: 24h
  allow_import: true
```

`upload_directory` should be writable only by the Central service account. Uploaded files are created with generated names and are never stored using a user-supplied path.

## Workflow

1. Open **Analysis** in Central.
2. Select the target sensor.
3. Select a `.pcap` or `.pcapng` file.
4. Keep Auto detect, Modbus/TCP and Siemens S7comm selected as required.
5. Click **Upload and analyze**.
6. The job changes from `queued` to `running` when the sensor claims it.
7. The sensor pauses live packet capture, downloads the file, verifies and analyzes it, then resumes live capture.
8. The job shows packet count and the number of newly discovered assets, flows, OT tags and alerts.

## Security controls

- management-token authentication for browser upload;
- sensor-token authentication for claim, download and result upload;
- only `.pcap` and `.pcapng` extensions;
- PCAP/PCAPNG magic-byte validation;
- configured upload size limit;
- generated storage filename;
- SHA-256 stored with every job;
- file deletion through the Analysis table;
- all management write operations pass through the Central audit middleware and can be exported to SIEM.

## API

Management listener:

```text
GET    /v1/analysis/jobs
POST   /v1/analysis/jobs               multipart: sensor_id, pcap, protocols
DELETE /v1/analysis/jobs/:job
```

Sensor listener:

```text
GET  /v1/sensors/:id/analysis/jobs/next
GET  /v1/sensors/:id/analysis/jobs/:job/pcap
POST /v1/sensors/:id/analysis/jobs/:job/result
```

## Modbus and S7

The import does not use a separate simplified decoder. Packets enter the existing sensor pipeline, therefore current Modbus/TCP and S7comm decoding, asset discovery, topology, OT tags and detection rules apply exactly as they do to live traffic.

## Operational notes

The selected sensor must be online and synchronizing with Central. Job pickup follows the configured Central synchronization interval. During file replay, live pcap capture is paused to prevent historical and live traffic from being interleaved. IPFIX-only sensors do not have a local pcap capture engine and report the job as failed.
