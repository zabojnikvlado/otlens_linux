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
