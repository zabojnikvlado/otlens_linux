# OTLens configuration

OTLens uses two independent configuration files.

## Linux Sensor

Use `sensor.config.example.yaml` as the template. The sensor binary loads:

```bash
/etc/otlens/config.yaml
```

Override with:

```bash
otlens --config /path/to/config.yaml
```

## Central Management

Use `central.config.example.yaml` as the template. The Central binary loads on Windows:

```text
C:\ProgramData\OTLens\config.yaml
```

Override with:

```powershell
.\otlens-central.exe --config C:\path\to\config.yaml
```

The Central config contains the PostgreSQL connection settings. The Sensor config contains capture, local SQLite, and Central endpoint settings.

## libpcap

`capture.mode: pcap` requires libpcap 1.10.0 or newer on the Linux sensor. The version is checked from the linked runtime library during startup. `capture.mode: ipfix` does not require libpcap at runtime.

## Ready-to-copy Linux sensor configuration

`configs/sensor.config.yaml` contains the complete sensor configuration, including the outbound `central:` connection block. Copy it to the sensor's default location and edit the URL, sensor ID, and token:

```bash
sudo install -d -m 0750 /etc/otlens
sudo install -m 0640 configs/sensor.config.yaml /etc/otlens/config.yaml
```
