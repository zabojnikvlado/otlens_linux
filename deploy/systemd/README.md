# OTLens on Linux (systemd)

Both unit files assume a dedicated `otlens` user/group and expect the
binary plus its config already in place — they don't create any of that
for you.

## Sensor (`otlens.service`)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin otlens
sudo mkdir -p /opt/otlens /etc/otlens /var/lib/otlens /var/log/otlens
sudo cp bin/otlens /opt/otlens/otlens
sudo cp configs/sensor.config.example.yaml /etc/otlens/config.yaml
# edit /etc/otlens/config.yaml: central.host/port/token, capture.interface
sudo chown -R otlens:otlens /opt/otlens /var/lib/otlens /var/log/otlens
sudo cp deploy/systemd/otlens.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now otlens
```

The unit grants `CAP_NET_RAW`/`CAP_NET_ADMIN` so packet capture works
without running the process as root — no further capability setup needed.

## Central (`otlens-central.service`)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin otlens
sudo mkdir -p /opt/otlens-central /etc/otlens-central
sudo cp bin/otlens-central /opt/otlens-central/otlens-central
sudo cp configs/central.config.example.yaml /etc/otlens-central/config.yaml
# edit /etc/otlens-central/config.yaml: database.*, auth.*
# Central looks for the UI at web/central *relative to the executable* by
# default (override with the OTLENS_CENTRAL_WEB_DIR env var instead) — so
# this must land at /opt/otlens-central/web/central, not .../central.
sudo mkdir -p /opt/otlens-central/web
sudo cp -r web/central /opt/otlens-central/web/
sudo chown -R otlens:otlens /opt/otlens-central
sudo cp deploy/systemd/otlens-central.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now otlens-central
```

Central's default config path is `config.yaml` next to its own
executable (`/opt/otlens-central/config.yaml` here) — since this setup
keeps the config in `/etc/otlens-central/` instead, the unit file passes
`--config /etc/otlens-central/config.yaml` explicitly. Make sure your
config actually lives wherever `ExecStart=` in the unit file points, or
just drop `config.yaml` next to the binary in `/opt/otlens-central/` and
remove `--config` from the unit entirely.

See `../../DOCUMENTATION.md` for what to put in each config file and how
to log in for the first time once the service is running.
