# S&P-100 Data, Platform & Edge Layer Hunt (2026-10-23)

Round 11B covers open-source software that S&P 100 companies run on their data and edge paths:
- telemetry ingestion (OpenTelemetry Collector and distributions, Fluent Bit);
- message brokers and their client-side allowlists (Kafka, RabbitMQ, ActiveMQ/Artemis, NATS, Pulsar);
- big-data file and table formats (Parquet, Avro, Arrow, ORC, Iceberg, Delta);
- token validation and cache isolation in the identity SDKs of the large cloud vendors;
- edge-proxy and service-mesh policy enforcement.

Five hunters each had an independent skeptic, and High findings went to a second judge. Everything ran locally
with self-generated keys and tokens, and no real service was contacted.

> **Disclosure status:** 3 confirmed vulnerabilities (1 High and 1 Medium, both upheld by the second judge;
> 1 more Medium), all **unpatched**. Counts are deliberately not broken down by track, because some tracks map
> to a single product. Details are embargoed until fixes ship.

## Results (aggregate)

| Class | Confirmed |
|---|---|
| An authentication check that doesn't apply the router's path normalization, so a crafted path reaches a protected route without the required credential (a **missed sibling** of a recent fix) | 1 (**High**) |
| A path-policy bypass via encoded path segments: an **incomplete fix** of a recent CVE | 1 (Medium) |
| An identity SDK validator that chooses its trusted key set from an unverified token header and never checks the issuer. Tokens from one issuer are accepted where another is expected (cross-issuer confusion) | 1 (Medium) |

## Publishable negatives
- **OpenTelemetry Collector:** shared HTTP server config enforces auth → size limit → decompression in that
  order for every codec. The CVE-2024-36129 fix is intact. The per-receiver decompression gaps we found were
  already known or fixed upstream.
- **Fluent Bit:** the Trace API sibling of CVE-2024-4323 is fully type-checked. About 2,800 mutated inputs
  across the http, OpenTelemetry, forward, syslog, Splunk and remote-write inputs caused no crash on the release
  build.
- **Message brokers:** the NATS auth-callout response validation, the Pulsar proxy target validator, the ActiveMQ
  OpenWire throwable instantiation guard, and Kafka's JAAS login-module allowlist all hold. Kafka's OAuth
  allowed-URLs check can be bypassed by following an HTTP redirect, which is hardening under the standard threat
  model.
- **Data formats:** no new schema-driven class-instantiation path in parquet-java, Avro Java or pyarrow. The
  2024–25 fixes hold, and the remaining validator gaps are already known. Several resource-exhaustion aborts in
  readers are bugs under those projects' policies.
- **Identity SDKs:** the multi-tenant issuer validation, token-cache plugins and JWT verifiers we tested are
  sound by default. The remaining gaps are documented or hardening.

## Takeaways
1. **Fix every filter, not just the one in the CVE.** When a path-normalization option exists, every policy filter
   (authn, authz, rate limit) must match on the same normalized path as the router. A fix applied to one filter
   is a map to its siblings.
2. **Never let the token choose its own trust anchor.** Key-set selection must come from the expected issuer,
   not from an unverified header field, and `iss` must always be checked.
3. **The mature ingestion paths are in good shape.** The residual risk is per-receiver or per-plugin code that
   re-implements decompression or decoding outside the shared hardened path.
