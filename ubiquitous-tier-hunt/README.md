# Ubiquitous-Tier Novelty Hunt — HTTP smuggling, proxy path confusion, and the big C libraries (2026-10-23)

The question driving this round: *of the software that sits in front of or underneath almost every
application and company today, where is a new, independently-discoverable vulnerability most likely?*

So this round deliberately left the language-runtime surface (Node/Deno/Bun/stdlibs, rounds 1–2) and
attacked the **shared tier**: the reverse proxies every request passes through, and the C libraries every
stack links. Seven parallel hunters, each with an independent skeptic that rebuilt the lab from scratch and
deduplicated hard against the public literature.

> **Headline: 0 novel vulnerabilities.** This is a genuine, well-evidenced negative, and it is the honest
> expected result for this tier — it is the most heavily researched and continuously OSS-Fuzzed code in the
> ecosystem. What the round *did* produce is a reusable differential lab, and a map of **N-day exposure**
> (already-public CVEs that still bite pinned-old versions). Nothing here is embargoed; everything below is
> already public or by-design, which is why this round is written up in full rather than held back.

## Targets and why they qualify as "almost every company"

| Hunter | Target | Ubiquity |
|---|---|---|
| HTTP/1.1 smuggling matrix | nginx 1.24 + HAProxy 2.8 front-ends × 10 back-ends (Go, Node 26/24, Deno node:http + Deno.serve, Bun node:http + Bun.serve, Python, Java, PHP) | nginx + HAProxy front a majority of the web |
| Path-confusion / access-control bypass | same proxies × 9 backend path interpreters | every app with a path-based auth rule behind a proxy |
| HTTP/2 → HTTP/1.1 downgrade | nginx + HAProxy as h2 front-ends, 6 backends | nearly every edge speaks h2 to clients, h1 to origins |
| libxml2 | 2.9.14 (system) vs master/2.15–2.16 | XML in SOAP, SAML, office/SVG, Android, Apple frameworks |
| curl + zlib / c-ares / nghttp2 | curl 8.5.0 and its deps | in essentially every container, CI image, phone, OS |
| SQLite | 3.45.1 / 3.53.4 / 3.54.0 | every browser, phone, OS; `node:sqlite`, `bun:sqlite` |
| Redis | 7.0.15 RESP parser + Lua EVAL | the default cache/session/queue store |

## What was actually run (not a desk review)

| Hunter | Scale | Result |
|---|---|---|
| Smuggling matrix | **2,178 case-measurements** (94 ambiguous messages × every pairing + all 4 proxy→proxy chains), keep-alive upstream on so a desync would persist | **0 reproducible desyncs** (0 cross-connection victim poisonings) |
| Path confusion | ~80 path vectors × 2 proxies (nginx in 3 modes) × 9 backends, raw-forward oracle | 0 product bugs; 3 **configuration/by-design** footguns (below) |
| HTTP/2 downgrade | ~60 malformed-h2 cases × 5 proxy configs (incl. h2c prior-knowledge) → raw-byte backend logger | 0 CRLF-injection / length-disagreement downgrades |
| libxml2 | both versions built clang-18 ASan+UBSan, OSS-Fuzz harnesses, **~1.04M execs** on master HEAD | 0 novel memory-safety crashes on current upstream |
| curl deps | zlib inflate **2.2M execs**; curl_url **5.7M execs**; 21-case adversarial-response battery; nghttp2/c-ares checks | 0 crashes; deps confirmed patched (incl. the Ubuntu CVE-2024-28182 backport) |
| SQLite | SQL-text fuzzer **787k execs**, DB-file fuzzer **325k execs**, ASan+UBSan, 9 CVE-area probe families, 3-version differential | 0 crashes on current upstream |
| Redis | source-built ASan+UBSan 7.0.15, **2.6M-iteration** RESP/Lua-lib fuzz + cross-state probes + upstream diff | 0 novel; 1 N-day (below) |

Full matrices, harnesses and raw repro bytes are archived privately (they are large and some raw request
corpora read like attack strings out of context); this README is the public account.

## The only things that *did* reproduce — and why none is a new vulnerability

**By-design / configuration footguns** (operator-controlled, documented, no product fix owed):
- **HAProxy `path_beg` without `normalize-uri`** forwards the raw target, so `/public/../internal`, `%2e%2e`,
  `%2f` reach a backend that resolves them — a path-based deny is bypassed. HAProxy ships `http-request
  normalize-uri` precisely for this; it is documented behavior (Orange Tsai, BH-US-2018).
- **Go 1.22+ `ServeMux`** matches on the *escaped* path and treats `%2f` as in-segment, so `/internal%2fsecret`
  misses an `/internal/` guard and falls through to a `/` FileServer that opens the decoded path. Documented in
  the Go 1.22 routing change; `GODEBUG=httpmuxgo121=1` restores old behavior.
- **nginx `merge_slashes off`** stops `//internal` from collapsing, breaking a prefix `location` deny. Documented
  footgun; default (`on`) is robust and 400s traversal-above-root, `%00`, and encoded dot-segments.

These matter — they are behind countless real-world bypasses — but the fix is *configuration*, not a code change,
so each is "not a product vulnerability."

**Parser laxities with no reachable desync** (correct as deployed):
- HAProxy accepts obs-fold `Transfer-Encoding` but **unfolds to canonical `chunked` before forwarding** (RFC 9112
  §5.2 permits SP-replacement); nginx 400s it. No backend ever sees ambiguity.
- nginx accepts bare-LF but **rewrites to CRLF and de-chunks on forward**; the raw ambiguity never leaves it.
  (The bare-LF *chunk-line* variant is already fixed on nginx master — the Jan-2024 CR-before-LF patch — and is
  the same class as Go CVE-2025-22871 and Netty CVE-2025-58056.)
- Python `http.server` is the most lenient backend (first-wins duplicate CL, ignores TE, reads a HEAD body), but
  CPython documents it as **not for production**, and behind nginx/HAProxy every such input is normalized or
  rejected first. Confirmed: 0 victim-poison across all proxied chains.
- Deno.serve / Bun.serve consume but don't surface a GET/HEAD body to the handler — **wire framing is correct**
  (the next request parses intact), so it's an API quirk, not a length disagreement.

**N-day exposure** (already-public CVEs; the lab's pinned-old versions are affected, current upstream is not):
- **SQLite `json_tree`/`json_each` on malformed JSONB** never terminates (50M-step cap hit) on 3.45.1 and 3.53.4;
  fixed by 3.54.0. Reachable wherever attacker-influenced JSONB meets those functions (incl. `node:sqlite`).
- **Redis 7.0.15 is EOL**, so it never got the Oct-2025 Lua fix cluster: it stays exposed to CVE-2025-46817
  (`bit.tohex` OOB) and the RediShell line (CVE-2025-49844 etc.). The fix is to upgrade off 7.0.x.
- curl 8.5.0 / nghttp2 1.59.0 *look* old but are Ubuntu-security-backported (the `.so` exports the
  CVE-2024-28182 fix symbol), so they are not actually exposed on this image.

## Takeaways
1. **The shared tier is hard ground for novel memory-safety / desync bugs, and that is itself the finding.**
   Millions of sanitizer-fuzz executions and 2,178 smuggling measurements produced zero novel bugs. nginx,
   HAProxy, libxml2-master, curl's deps, SQLite and Redis are continuously fuzzed and security-attended; dumb
   and differential hunting there is near its floor.
2. **The real risk in this tier is configuration and version pinning, not fresh code bugs.** The three path
   footguns and the SQLite/Redis N-days are where a real company actually gets hurt — a misconfigured proxy rule
   or a pinned-old embedded library, not a 0-day in nginx.
3. **Novel findings in rounds 1–2 came from *logic* surfaces** (permission models, identity/canonicalization,
   NUL boundaries) that fuzzers can't reach, and from *API reimplementations lagging fixes*. This round confirms
   the contrast: the memory-safety/parsing surface of the ubiquitous tier is the least productive place to look.

## Where to point the next dive (given this result)
The productive frontier is **not** more fuzzing of hardened C. It is logic and freshness:
- newer, less-audited protocol surfaces in the same ubiquitous products (HTTP/3 / QUIC stacks; gRPC; the proxies'
  Lua/JS/Wasm extension VMs),
- API-reimplementation lag (the round-1/2 pattern) in fast-moving reimplementations,
- and **supply-chain / N-day surface mapping** — which huge deployments still pin the exposed old versions above.
