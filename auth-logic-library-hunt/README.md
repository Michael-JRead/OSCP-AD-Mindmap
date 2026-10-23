# Auth / Request-Path Logic-Library Hunt — JWT, URL→SSRF, zip-slip, cookies, multipart (2026-10-23)

Round 4. Rounds 1–3 showed the productive frontier is **logic** bugs in widely used libraries, not
memory-safety fuzzing of hardened C. So this round tested the libraries that sit in the auth and
request path of almost every application, **across languages**, using cross-library differential
matrices. Each of 5 hunters was paired with an independent skeptic that re-ran every candidate on the
latest release and deduplicated against CVE databases.

> **Disclosure status:** 3 confirmed vulnerabilities (2 Medium, 1 Low), all **unpatched** as of
> 2026-10-23. Per-finding details are embargoed and held in a private disclosure package. This page
> gives method, coverage, aggregate results and the (publishable) negatives.

## Coverage

| Hunter | Libraries (latest, 2026-10-23) | Vectors |
|---|---|---|
| JWT / JOSE | 11 maintained verifiers across Node, Go, Rust, Ruby and PHP | 41 forged/tampered vectors: alg:none variants, HS/RS/ES confusion in every key encoding, kid traversal, embedded jwk/jku, crit, duplicate JSON keys, psychic/zero ECDSA, DER-vs-raw, truncated sigs, claim validation, base64 canonicalization |
| URL parser → SSRF | Node WHATWG URL / ada / url.parse, Go net/url, Ruby URI, Python urllib.parse + yarl + requests/urllib3, curl, Rust url | userinfo/backslash/CRLF/IDN/fullwidth/alt-dot/IPv4-form/mapped-IPv6/percent-encoding corpus; validator-host vs connected-host |
| Archive extraction | Python zipfile + tarfile, Node tar / adm-zip / unzipper / extract-zip / zip-lib / decompress, Go archive/* + mholt/archiver, Ruby rubyzip, Rust zip/tar | `../`, absolute, drive/UNC, symlink-then-write-through, hardlink, NUL/CRLF names, case tricks |
| Cookies | ~10 server- and client-side cookie parsers across Node, Go, Python, Ruby, Deno, Bun and PHP | `__Host-`/`__Secure-` prefix enforcement, name/value parsing differentials, duplicates, attribute parsing |
| Multipart | busboy / formidable / multer / undici FormData, Go mime/multipart, python-multipart / email, PHP, Rack | boundary edge cases, duplicate Content-Disposition, filename vs filename*, case, bare-LF, padding |

## Results

| | Count |
|---|---|
| Confirmed vulnerabilities (unpatched; embargoed) | **3** — two **Medium** session-fixation-class issues in the cookie handling of widely used web frameworks, one **Low** JWT claim-validation fail-open |
| N-day (fixed upstream; still in old pinned versions) | 3 archive extractors with known arbitrary-write CVEs (CVSS 6.4–8.1) — upgrade if you pin them |
| Non-security differentials / by-design | ~15 (JWT signature-encoding malleability, `crit` handling split between JWT and JOSE libraries, multipart first-vs-last-wins splits, Python `tarfile` unsafe-by-default without `filter=` — documented and transitioning) |

## Publishable negatives (useful on their own)

- **JWT forgery is closed.** In all 11 current libraries, every classic forgery is rejected by default:
  `alg:none` (incl. case/whitespace), RS/ES→HS algorithm confusion in every public-key encoding (incl.
  OIDC/JWKS paths), `kid` traversal, embedded `jwk`/`jku`, duplicate-key JSON, psychic/zero ECDSA,
  truncated/empty signatures. The 2015–2022 JWT bug era is over for maintained libraries. The live
  frontier is **claim-type handling** (what happens when `exp`/`nbf`/`aud` has an unexpected JSON
  type) — the class behind several 2026 CVEs.
- **URL parsing:** the remaining validator/fetcher splits are documented IDNA "ignored code point"
  behavior or already-public N-days (e.g. the `urllib.parse` vs `requests` backslash-authority split).
- **Archive extraction:** current defaults of the mainstream libraries contain traversal and
  symlink tricks; the dangerous results were all in **old pinned versions** of known-vulnerable packages.

## Takeaway
Same pattern as rounds 1–2: the bugs live where **one component validates a value and another acts on a
differently-normalized version of it** — here, a value interpreted one way by the party enforcing a security rule
and another way by the party that consumes it.
