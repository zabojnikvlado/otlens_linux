# Asset IP history in Asset Detail

The Asset Detail popup includes a dedicated **IP history** tab.

It loads the durable history for the selected sensor and MAC address from:

`GET /v1/sensors/:id/assets/by-mac/:mac/ip-history`

The table shows every observed IP address, first seen, last seen, observed duration, and marks the current IP. Assets without a MAC address display an explanatory empty state.
