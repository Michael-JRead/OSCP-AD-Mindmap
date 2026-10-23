# S&P-100 Infrastructure & Data Layer Hunt (2026-10-23)

Round 10B covers open-source infrastructure that S&P 100 companies build or run at scale:
- AI inference servers;
- Kubernetes ingress/gateway controllers (siblings of IngressNightmare);
- database drivers from the big cloud and database vendors;
- an anti-malware engine;
- the Go standard library;
- gRPC and protobuf.

Six hunters each had an independent skeptic, and High findings went to a second judge. Everything ran in-process
or on loopback. Controllers were tested at the template level (no cluster), and no real service was contacted.

> **Disclosure status:** 5 confirmed vulnerabilities (1 Moderate, 4 Low / Low-Medium), all **unpatched**. Details
> are embargoed, so affected projects are not named here. The AI-inference track's candidates are still in
> independent verification (round 10C) and are not counted yet.

## Results (aggregate)

| Track | Confirmed | Class |
|---|---|---|
| gRPC / protobuf | 1 (Moderate) | a quadratic-CPU case in the 2026 "nested `Any`" bug class, in a runtime where it had not yet been reported |
| Database drivers | 1 (Low-Medium) | an **incomplete fix** of a 2026 deserialization CVE in a driver plugin |
| Ingress / gateway controllers | 2 (Low-Medium) | a validator whose regex engine lets `$` match before a trailing newline, so a tenant route freezes config updates on a shared gateway; a validator regex anchored only at the start |
| Go standard library | 1 (Low) | quadratic header construction from an unbounded client cookie jar |
| Anti-malware engine | 0 | no memory-safety crash in bounded sanitizer fuzzing; parser differentials were filed as functional bugs, since the vendor's policy treats detection gaps as non-security |
| AI inference servers | pending | 3 candidates in verification (round 10C) |

## Publishable negatives
- **ingress-nginx v1.15.1:** no new directive injection across the annotation validators and template sinks
  reviewed after the 2025–2026 IngressNightmare-era fixes.
- **gRPC:** grpcio 1.84.1 rejects compressed bodies that inflate to 5, 64 or 512 MiB (RESOURCE_EXHAUSTED).
  grpc-go and grpc-java carry the decompression caps and the reset-accounting fixes (source review).
- **Go 1.27.3:** we reviewed 106 CVE-tagged commits since 2024. The quadratic-fix siblings in textproto, mime
  and mail stay linear across 37 input shapes, and the query-limit and ReverseProxy re-encoding paths fail
  closed.
- **SGLang:** its ZMQ/pickle surfaces are already hardened (loopback binds, peer restriction, safe pickle loads).
- **Database-driver "confused deputy" cases**, where a user-controlled connection string causes ambient cloud
  credentials to be used, are documented driver semantics. The risk sits with platforms that accept arbitrary
  JDBC URLs from users. If you run such a platform, allow-list driver properties and hosts.

## Takeaways
1. **New bug classes spread across runtimes.** The nested-`Any` class was fixed in several protobuf runtimes
   during 2026 and still had an unreported quadratic path in another one.
2. **Validator regex semantics matter.** `$` means end-of-string in some engines and end-of-line in others. A
   validator for config that a different tokenizer will parse must use `\z`, or explicitly reject CR/LF.
3. **Incomplete fixes again.** Deserialization allow-lists added by a fix need a size/complexity budget too.
