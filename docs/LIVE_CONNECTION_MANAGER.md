# Live Connection Manager

The Central web UI uses one shared `LiveConnectionManager` for the entire authenticated application shell.

Key behavior:

- exactly one `EventSource` connection per browser tab;
- tab navigation and normal data refreshes do not recreate the stream;
- reconnect delay uses 1, 2, 5, 10 and 30 second backoff steps;
- the attempt counter resets only after the stream remains stable for 10 seconds;
- interruptions shorter than 1.5 seconds do not change the badge, preventing visual flicker;
- the API polling state and live-stream state are tracked separately;
- a successful REST refresh no longer overwrites the live-stream badge;
- logout/session expiry closes the stream and cancels all reconnect timers;
- 60-second polling remains available as a consistency fallback.

The top-right badge is stable `live` while SSE is connected. It changes to `reconnecting` only for a sustained interruption, and to an API error when Central REST requests fail.
