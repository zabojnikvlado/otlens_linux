# Discovery hostname enrichment

Safe discovery now obtains hostname candidates from three non-authenticated sources, in priority order:

1. reverse DNS PTR lookup,
2. TLS certificate DNS SAN / common name,
3. hostname exposed by an HTTP redirect.

Only DNS-style names are accepted from TLS and HTTP. IP addresses, empty values, and wildcard prefixes are rejected. The selected value is persisted as `hostname` evidence and merged into the asset profile by Central.

A server that exposes only SSH without PTR DNS, TLS, HTTP redirect, or authenticated inventory cannot reliably disclose its operating-system hostname. In that case, authenticated SSH inventory remains the deterministic method.
