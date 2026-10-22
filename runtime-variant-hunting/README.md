# Cross-Runtime Variant Hunt — Node.js's 2025–26 CVE classes vs. other server runtimes

**Question:** which other major runtimes and dependencies are used the way PHP and Node.js are, and do
Node's just-fixed bug classes exist in them too?

**Method:** take each bug class Node.js fixed in 2025–26 and use Node's fixed behavior as the test
oracle. Replay the same inputs against runtimes that reimplement or parallel those APIs. All testing was
local, against processes we started.

> **Disclosure status: positives are embargoed.** Results are aggregated by vendor. Details go to each
> vendor's private channel first (Deno GHSA, Bun security email, CPython GHSA) and will be published
> here after fixes ship.

## Runtimes tested

| Runtime | Version | Why it matters |
|---|---|---|
| **Deno** | 2.9.8 (latest) | Reimplements `node:*` APIs; has its own permission system |
| **Bun** | 1.4.4 (latest) | Reimplements `node:*` APIs; huge adoption growth |
| CPython | 3.11.15 (positives checked against `main` / 3.14 / 3.15 source) | WSGI/ASGI backends |
| Go | 1.24.7 (checked against master) | `net/http`, `crypto/x509` |
| Java | OpenJDK 21.0.10 | `HttpsURLConnection`, `HttpClient`, `com.sun.net.httpserver` |
| Ruby | 3.3.6 (checked against ruby_3_4 / 4_0 / gem master) | Net::HTTP, OpenSSL, IPAddr |
| Perl | 5.38.2 | Socket, IO::Socket, HTTP::Tiny |
| PHP | 8.4.19 CLI (non-PHP2Shell surfaces only) | filter_var, parse_url, stream verify_peer_name, `php -S` |

## Classes replayed (the matrix)

| Class | Node reference CVEs | Tested in |
|---|---|---|
| TLS identity: non-canonical IPv4, Unicode digits/dots, wildcard, IP-vs-DNS SAN | 106072, 105483, 106069, 48618 | Deno, Bun, CPython, Go, Java, Ruby, Perl, PHP |
| NUL truncation into resolvers, sockets and process APIs | 105482 | Deno, Bun, CPython, Go, Java, Ruby, Perl, PHP |
| HTTP/1.1 framing and keep-alive response misattribution | 105481, 23167, 27982, 30589 | Deno.serve, Bun.serve, node:http compat, CPython, Go, JDK, Ruby, `php -S` |
| Windows path joining (device names, drive-relative) | 27210, 23084 | Deno, Bun node:path, CPython `ntpath` |
| Permission-system bypasses (fd ops, symlinks, aliases, special paths) | 36137, 55132, 55130, 21636, 106073 | Deno (Bun has no permission model) |

## Results (aggregate)

| Vendor | Confirmed vulnerabilities | Other |
|---|---|---|
| Deno | **4** (low to low–medium) | — |
| Bun | **1** (medium–low) | 1 hardening gap (to be reported) |
| CPython | **1** (low) | 1 hardening bug (to be reported) |
| Ruby | — | 1 hardening bug (to be reported); IPAddr mapped-address issues **already fixed** upstream ([ruby/ipaddr#65](https://github.com/ruby/ipaddr/pull/65), [#106](https://github.com/ruby/ipaddr/pull/106)) |
| Go | — | CL+TE keep-alive **already fixed** on master ([golang/go#80942](https://github.com/golang/go/issues/80942)) |
| Java / Perl / PHP-CLI | — | Low-confidence leniencies only (unverified; not filed) |

## Takeaways
1. **API reimplementations lag the original's security fixes.** Deno and Bun mirror Node's APIs but not
   always Node's CVE fixes. A runtime that just patched an API makes its fixed behavior a free test
   oracle for every runtime that copies that API. This was the highest-yield idea in the whole hunt.
2. **Each security system's own CVEs have siblings.** A permission system's past advisories are the
   best map for its next ones, the same pattern as Node's 2026 regression chains.
3. **Old classes persist in standard libraries.** NUL truncation at the C boundary was fixed piecemeal
   across stdlibs. Where one function rejects NUL and its sibling doesn't, that inconsistency is the
   finding.
