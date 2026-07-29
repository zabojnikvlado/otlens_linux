# Dashboard lazy-data and operational-warning fix

The dashboard now loads every dataset used by its KPI cards during the dashboard refresh, including detection rules, OT tags, assets, sensor metrics, analysis jobs, backups, vulnerability summaries, SMB observations, and reconnaissance jobs. This prevents cards from showing zero until their corresponding detail tab has been opened.

Operational warnings now count unique affected sensors. Warning and critical states are read from sensor metrics, while stopped and offline states are also read from the sensor registry because those sensors may not produce a current metrics record.
