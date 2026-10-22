# Persistent-worker runtimes and shared libraries: where PHP2Shell- and Node-Brotli-style bugs could recur (as of 2026-10-22)

**Scope.** This is defensive variant analysis: read-only research, local source and binary inspection, and public sources. It contains no exploitation mechanics. Each claim carries a tag:
- **[L]** checked locally in the lab or in an upstream git checkout
- **[P]** primary source (vendor advisory, upstream changelog or commit)
- **[S]** secondary coverage
- **[I]** my own inference

---

## TL;DR

1. **The Node Brotli CVE-2026-111497 is an upstream google/brotli bug, not a Node binding bug [L][P].**
   - Node's fix is `deps: brotli: cherry-pick 0ed4268a4401abcb44720963 (Evgenii Kliuchnikov)`. The only change in Node's own `src/` is exposing the new `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` constant.
   - Upstream tagged **v1.2.1, v1.1.1 and v1.0.10 on 2026-10-21**. Each tag is the old base plus that single commit. The 1.2.1 CHANGELOG reads: *"SECURITY – CVE-2026-111497: out-of-bounds write permits remote code execution."*
   - **Patch gap: the fix commit had been public on `master` since 2026-02-27 (236 days) under the neutral title "Detect and report invalid stream earlier."**
2. **Brotli exposure is wide.** Any product that vendors the C decoder (1.0.3 through 1.2.0) without that commit is exposed.
   - **Every product that vendors the C decoder must pick up the fix itself. Downstream status for specific products is withheld pending private vendor notification.**
   - Ports in other languages (Rust, Go) were reviewed at the source level. Any notes go to their maintainers first.
   - Bun 1.4.4's binary carries the fix's new error-code name, which suggests it is already fixed [L/I].
3. **PHP2Shell is two bug classes [P]:**
   - **CVE-2026-109618:** an out-of-memory `longjmp` bailout interrupts initialization, and shutdown later trusts the half-built state.
   - **CVE-2026-109619:** worker-wide globals point into request memory and survive skipped resets.
   - The php-src fix (commit `506e87f`, 402 files) replaces the bailout with an `UnwindExit` plus a hard-limit `_exit(137)`, and adds early resets. It also adds a **fail-the-Nth-allocation hook, `ZEND_MM_MAX_ALLOCS`** [L].
   - **It does not touch out-of-tree SAPIs or PECL extensions** [L]. That is where the residual variant space is.
4. **Class (b) is already recurring.** FrankenPHP worker mode published three cross-request state leaks in 2026: CVE-2026-24894, CVE-2026-82416 and GHSA-4gfw-9v29-gp9h [P]. Java containers, Puma/Rails and Perl FCGI have older precedents.
5. **Most plausible new variants:**
   - **Swoole/OpenSwoole coroutines** under the new OOM-unwind behaviour, plus **APM/PECL extensions** in persistent workers
   - **HAProxy Lua** (`tune.lua.maxmem` is a custom allocator that returns NULL, followed by a `longjmp`)
   - **Redis/Valkey Lua** (one persistent Lua VM shared by all clients)
   - **PostgreSQL extensions** (`elog(ERROR)` `longjmp` combined with memory contexts)
   - the unpatched Brotli copies above
   - Java container object recycling
6. **Patch hygiene:** check every bundled and system brotli copy you run (marker method in §2.2), and update PHP runtimes to the fixed releases.
   - The PHP CLI is 8.4.19, which is older than the fixed 8.4.27.

---

## 1. Landscape: major server-side runtimes and platforms (October 2026)

**Adoption signals**
- **Server-side languages (W3Techs, share of sites with a known server-side language):**
  - PHP **69.3%**
  - JavaScript 7.2%
  - Ruby 7.0%
  - Java 5.5%
  - Scala 5.1%
  - The non-PHP figures are from the Aug 27, 2026 snapshot. JavaScript passed Ruby for second place in July 2026. [S, W3Techs pages]
- **Web servers (W3Techs, Oct 22, 2026):**
  - Cloudflare 32.6%
  - nginx 30.2%
  - Apache 21.3%
  - LiteSpeed 13.9%
  - Node.js 7.4%
  - IIS 2.9%
  - The Cloudflare number counts reverse proxies, not origin servers. [S]
- **Developer usage (Stack Overflow survey 2026):**
  - Node.js 46.4%
  - ASP.NET Core 19.9%
  - FastAPI 18.5%
  - Express 15.6%
  - ASP.NET 13.9%
  - Spring Boot 12.8%
  - Flask about 12.5% (the snippets conflict)
  - Django 11.3%
- I did not retrieve Netcraft figures.

| Runtime / platform | Persistent-worker model (what PHP2Shell class (b) needs) | Main HTTP stack | Security reporting |
|---|---|---|---|
| **PHP** (Zend engine) | mod_php (Apache), PHP-FPM, LSAPI (`lsphp`), php-cgi in FastCGI mode (IIS), **FrankenPHP worker mode**, **Swoole/OpenSwoole**, RoadRunner (CLI worker loop), uWSGI PHP plugin, NGINX Unit (**archived Oct 2025, unmaintained** [S]) | SAPI-dependent | GitHub advisories on php/php-src [P] |
| **Node.js** | Single long-lived process by design | llhttp + undici | [HackerOne](https://hackerone.com/nodejs) [L, SECURITY.md] |
| **Deno** 2.9.8 | Long-lived process | hyper / h2 / quinn (Rust), rustls + aws-lc-rs, hickory DNS [L] | SECURITY.md (deno) |
| **Bun** 1.4.4 | Long-lived process; uWebSockets/usockets object reuse | Zig + JavaScriptCore, BoringSSL [L] | GitHub advisories (oven-sh/bun) |
| **Python** (CPython 3.x) | Gunicorn prefork, uWSGI (**maintenance mode** [S]), Uvicorn/Hypercorn (ASGI), Granian | WSGI / ASGI | PSRT (security@python.org) |
| **Java** (OpenJDK) | Tomcat, Jetty, Undertow, Netty / Reactor-Netty, Spring | Thread pools with request/response object recycling | ASF, Eclipse, Netty GHSA, Red Hat |
| **.NET / ASP.NET Core** | Kestrel (pooled `HttpContext`, pipelines memory pools) | Kestrel | MSRC |
| **Go** | net/http, fasthttp / Fiber (heavy context reuse) | Pure Go | Go vulndb / project policies |
| **Ruby** (MRI) | Puma (threads + cluster), Unicorn, Passenger, Falcon; Rails executor / CurrentAttributes | Rack | Ruby / Rails HackerOne; Puma GHSA |
| **Perl** | mod_perl, FCGI / CGI::Fast, Starman, hypnotoad | PSGI / FastCGI | CPAN maintainers |
| **Lua / OpenResty** | nginx workers with `lua_code_cache` (module tables persist across requests) | nginx | OpenResty |
| **Front ends** | nginx, Apache httpd (prefork + mod_php), Caddy (Go; FrankenPHP is built on it), LiteSpeed, IIS, Envoy, HAProxy | — | security-alert@nginx.org, ASF, envoy-security@googlegroups.com, HAProxy |

Recent headline CVEs in this landscape include:
- [CVE-2025-55315](https://nvd.nist.gov/vuln/detail/CVE-2025-55315): Kestrel request smuggling.
- nginx 2026: [CVE-2026-97205](https://my.f5.com/manage/s/article/K000162608) (use-after-free with AIO + SSI) and CVE-2026-42530 (HTTP/3 use-after-free), fixed in 1.30.6 and 1.31.7 [S].
- [CVE-2025-23419](https://nvd.nist.gov/vuln/detail/CVE-2025-23419): nginx TLS session resumption shared across server blocks bypasses client-certificate checks.

---

## 2. Shared-dependency blast radius

### 2.1 Who bundles and who links the shared native libraries

| Library | Bundled (patched only by the vendor) | Usually system-linked (patched by distros) | Recent precedent |
|---|---|---|---|
| OpenSSL / BoringSSL / AWS-LC | Node (OpenSSL 3.5.9) [L]; Bun (BoringSSL) [L]; Envoy (BoringSSL) | PHP, Python, Ruby, nginx, httpd, HAProxy, curl, .NET on Linux | OpenSSL [CVE-2025-15467](https://nvd.nist.gov/vuln/detail/CVE-2025-15467) (pre-auth stack overflow in CMS parsing); 3.5.9 rebase fixes 14 CVEs [S] |
| zlib / zlib-ng | Node (Chromium "motley" zlib) [L]; .NET (zlib-ng) [L]; Bun (zlib + libdeflate) [L] | PHP, Python, Ruby, nginx | [CVE-2022-37434](https://nvd.nist.gov/vuln/detail/CVE-2022-37434) |
| **brotli (decoder)** | **Node, Bun, .NET, Envoy, PyPI Brotli/brotlicffi wheels, brotli4j (Netty), Ruby `brotli` gem, PHP ext-brotli, Chromium/Electron** | curl/libcurl, FreeType (WOFF2), libjxl (`brob` boxes) | **CVE-2026-111497**; [CVE-2020-8927](https://nvd.nist.gov/vuln/detail/CVE-2020-8927); Envoy [CVE-2024-32976](https://nvd.nist.gov/vuln/detail/CVE-2024-32976) |
| zstd | Node 1.5.7, Bun, .NET [L] | curl, PHP | — |
| libxml2 | — | PHP, Python lxml, Ruby Nokogiri (often vendored), httpd | Maintainer ended embargoes in mid-2025 and stepped down 2025-09-15 [S] |
| c-ares | Node 1.34.9 [L]; Bun (pinned commit) [L] | curl, gRPC | [CVE-2026-33630](https://security-tracker.debian.org/tracker/CVE-2026-33630) (use-after-free / double free, fixed in 1.34.7); [CVE-2025-31498](https://nvd.nist.gov/vuln/detail/CVE-2025-31498) |
| nghttp2, llhttp, libuv | Node [L]; Bun (llhttp-compat, usockets) | httpd mod_http2, curl | — |
| SQLite | Node 3.54.0, Deno (libsqlite3-sys), Bun 3.53.4 [L] | PHP pdo_sqlite, Python | [CVE-2019-20218](https://nvd.nist.gov/vuln/detail/CVE-2019-20218) |
| ICU, PCRE2 | Node / Bun ICU 78.3 [L]; PHP bundles PCRE2 | — | — |

**Software-composition-scanner pitfalls [L]:**
- Patched Node 26.12.1 and 24.22.1 still report `process.versions.brotli = "1.2.0"`, because the cherry-pick did not bump `version.h`.
- Deno's `process.versions` (`brotli 1.2.0`, `openssl 3.0.7+quic`, `ares 1.34.6`) is a compatibility shim. Deno actually uses Rust crates.

### 2.2 CVE-2026-111497: upstream or binding?

**Answer: upstream google/brotli C decoder (`c/dec/decode.c`).** Evidence:
- Node's 26.12.1 changelog lists `deps: brotli: cherry-pick 0ed4268a4401abcb44720963 (Evgenii Kliuchnikov)` and `src: expose BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` [L].
- The upstream commit 0ed4268 ("Detect and report invalid stream earlier.", 2026-02-27) touches only `c/dec/decode.c` and `c/include/brotli/decode.h` [L].
- Release tags v1.2.1, v1.1.1 and v1.0.10 each equal "base + this commit + version bump". The CHANGELOG names the CVE [L].
- Node's advisory names no root-cause location [P].

**Root cause (high level).** The public fix makes failure results in the decoder's fast path, which were previously ignored, propagate as errors. It also fills the previously reserved error slot `-17` with `BLOCK_SWITCH`, which gives a simple marker for checking whether a copy is fixed [L].
- The early-failure guard that the fast path ignored first appears in **v1.0.3**; v1.0.2 does not have it [L].
- That matches the reported affected range of 1.0.3 through 1.2.0, with fixes in 1.0.10, 1.1.1 and 1.2.1 [S/I].

This is the same family as PHP2Shell (a failure signal is dropped and later code trusts inconsistent state), but it is a state-machine bug, not a `longjmp`.

**Checking whether a copy has the fix [L]:**
- **In source:** `decode.h` contains `BROTLI_ERROR_CODE(_ERROR_FORMAT_, BLOCK_SWITCH, -17)`, or `version.h` is at least 1.2.1, 1.1.1 or 1.0.10.
- **In binaries:** `strings | grep _ERROR_FORMAT_BLOCK_SWITCH`. A hit means the fix is likely present. No hit, while `_ERROR_FORMAT_DISTANCE` is present, means a pre-fix error table. A distro could still ship a minimal backport without the new enum, so check its changelog.

**Downstream status as of 2026-10-22:**

| Consumer | Status |
|---|---|
| Node 22.23.4 / 24.22.1 / 26.12.1 | Fixed [P][L]. Reachable unauthenticated through `fetch()` with `Content-Encoding: br`, `zlib`, and Express 5's body parser decompressing br request bodies [S] |
| Bun 1.4.4 | Binary contains `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` and `ERR__ERROR_FORMAT_BLOCK_SWITCH`, which suggests the fix is present [L/I]. Confirm with Bun |
| Other bundled copies and ports: .NET, Envoy decompressor filter, brotli4j (Netty), Ruby `brotli` gem, PHP ext-brotli, Chromium `third_party/brotli` / Electron, and Rust/Go ports | Check each one against the marker above. Status for specific products is withheld pending private vendor notification |
| Java `org.brotli:dec` and the pure-Go `go/brotli` in the upstream repo | Different code structure; this pattern is not present [L] |
| PyPI `Brotli` 1.2.1 and `brotlicffi` 1.2.1.0 | Published 2026-10-22 [L]. Upgrade these, because urllib3, requests, httpx and aiohttp decode br automatically when they are installed |
| System `libbrotlidec` (curl, FreeType WOFF2, libjxl) | Needs the distro update. Check your distro's security tracker |
| Not affected (encoder only) | nginx `ngx_brotli`, Apache `mod_brotli` |

---

## 3. Variant map of the PHP2Shell class

**The class, from the advisories [P]:**
- **(a) CVE-2026-109618:** an out-of-memory `longjmp` bailout fires while request memory is already reachable but not yet initialized. Request shutdown then processes the half-built state. The failing allocation does not need to be related to that state.
- **(b) CVE-2026-109619:** request-owned state is held in worker-wide globals. A fatal error (out of memory or timeout) can skip the matching reset, or a shutdown-time warning can repopulate state after the reset. "Early consumers" (startup INI diagnostics, session upload-progress handling) then use the dangling reference.
- Confirmed on mod_php. FPM, FrankenPHP and LSAPI are assessed as conditional or likely.
- Fixed in **8.2.35, 8.3.36, 8.4.27 and 8.5.12**.

**What the fix does (php-8.4.27, commit 506e87f) [L]:**
- Out of memory now becomes `zend_throw_unwind_exit()` at the next VM safe point (a soft limit).
- A new INI setting, `memory_hard_limit_percent`, defaults to 200% when the limit is under 1 GB and a fixed 1 GB buffer otherwise. Crossing it calls `_exit(137)`.
- Integer-overflow allocation errors are also delayed.
- Resets now run before RINIT (`php_basic_early_rinit`, session `in_rfc1867_update`, among others).
- New test hook: `USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1 ZEND_MM_MAX_ALLOCS=N` fails "the n-th allocation of the request in the same way as the memory limit would".
- Changed files: `main/`, `Zend/`, about 30 bundled extensions, `sapi/fuzzer` and `sapi/phpdbg`. **No changes in `sapi/apache2handler`, `sapi/fpm`, `sapi/cgi`, `sapi/litespeed` or `sapi/embed`, and none in out-of-tree code.**
- **Residual-risk note [I]:** in thread-safe (ZTS) servers such as FrankenPHP or threaded mod_php, the hard-limit `_exit` kills the whole process and every in-flight request. Size the hard limit with that in mind.

### 3.1 Matrix

| Runtime / product | Non-local exit, or recoverable out-of-memory with a soft limit? | Persistent process-wide state across requests? | Precedents (same or adjacent class) | Plausibility |
|---|---|---|---|---|
| **PHP, out-of-tree** (Swoole/OpenSwoole, FrankenPHP worker, PECL/APM extensions) | Yes. Out of memory is now `UnwindExit`; other `E_ERROR` paths still bail out | Yes: module globals, coroutine executor-globals swaps, worker loops | [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp), [CVE-2026-24894](https://github.com/advisories/GHSA-r3xh-3r3w-47gp), [CVE-2026-82416](https://github.com/advisories/GHSA-v3ph-cgqh-r8p5), [GHSA-4gfw-9v29-gp9h](https://github.com/php/frankenphp/security), [CVE-2021-21703](https://nvd.nist.gov/vuln/detail/CVE-2021-21703), [CVE-2019-11043](https://nvd.nist.gov/vuln/detail/CVE-2019-11043) | **High** |
| **HAProxy Lua** (`hlua`) | Yes. `tune.lua.maxmem` is a custom allocator that refuses memory, after which "the current Lua execution is terminated with an error and HAProxy continues" [S, HAProxy docs], via `luaD_throw` | Yes: shared or per-thread Lua state across streams | No verified CVE in this class located | **High** |
| **Redis / Valkey Lua** | Script `error()` / `luaL_error` raised from C helpers. Redis's own allocator aborts on out of memory | Yes: one VM shared by all clients and scripts | [CVE-2021-32626](https://nvd.nist.gov/vuln/detail/CVE-2021-32626), [CVE-2024-46981](https://nvd.nist.gov/vuln/detail/CVE-2024-46981), [CVE-2025-49844](https://redis.io/blog/security-advisory-cve-2025-49844/), [CVE-2025-46817](https://nvd.nist.gov/vuln/detail/CVE-2025-46817), [CVE-2025-46818](https://nvd.nist.gov/vuln/detail/CVE-2025-46818) (cross-user metatables), [CVE-2025-46819](https://nvd.nist.gov/vuln/detail/CVE-2025-46819) | **High** |
| **PostgreSQL** (core + extensions) | Yes. `elog(ERROR)` uses `siglongjmp`; `palloc` failure and `MaxAllocSize` raise recoverable ERRORs; memory contexts are reset on abort | Yes: backend-lifetime statics, caches, hook nesting counters | [CVE-2024-10978](https://www.postgresql.org/support/security/CVE-2024-10978) (wrong user ID after a reset), [CVE-2024-10976](https://nvd.nist.gov/vuln/detail/CVE-2024-10976) (reused query), [CVE-2021-23214](https://nvd.nist.gov/vuln/detail/CVE-2021-23214) (pre-TLS bytes survive the transition) | **High** (extensions) |
| **Lua (PUC 5.x) embedders** | Yes. `LUA_ERRMEM` through `luaD_throw` when the allocator returns NULL | Embedder-dependent | Lua [e752d84](https://github.com/lua/lua/commit/e752d84ed8250820aa3f6a097e008de6c2ec8322) "memory-allocation error when resizing a table can leave it in an inconsistent state" (found right after `T.allocount` was added, [cc01d46](https://github.com/lua/lua/commit/cc01d4624782e28c19b3c75ef7efda4b151dbf03)); [2297432](https://github.com/lua/lua/commit/22974326ca0d4f893849ce722cc1d65b3e228f42) (2025 use-after-free via emergency garbage collection); [c931d86](https://github.com/lua/lua/commit/c931d86e98da320c71da70c16d44aa28e9755520); [CVE-2020-15888](https://nvd.nist.gov/vuln/detail/CVE-2020-15888), [CVE-2021-44964](https://nvd.nist.gov/vuln/detail/CVE-2021-44964), [CVE-2022-33099](https://nvd.nist.gov/vuln/detail/CVE-2022-33099) (error raised during error handling) | Medium–High |
| **Java containers** (Tomcat / Jetty / Undertow / Netty) | `OutOfMemoryError` / `StackOverflowError` are throwable anywhere; limit-triggered exceptions (431 header limits, max post size) | Yes: request/response recycling, buffer pools | [CVE-2023-42795](https://nvd.nist.gov/vuln/detail/CVE-2023-42795) (an error skips part of recycling), [CVE-2019-17638](https://nvd.nist.gov/vuln/detail/CVE-2019-17638) (431 limit triggers a double release), [CVE-2022-25762](https://nvd.nist.gov/vuln/detail/CVE-2022-25762), [CVE-2024-7885](https://nvd.nist.gov/vuln/detail/CVE-2024-7885), [CVE-2024-21733](https://nvd.nist.gov/vuln/detail/CVE-2024-21733), [CVE-2021-25122](https://nvd.nist.gov/vuln/detail/CVE-2021-25122) | Medium–High (information leaks) |
| **Ruby** (MRI + Puma / Rails) | Yes. `rb_raise` / `NoMemoryError` `longjmp` through C extensions; `Thread#raise` and Rack::Timeout inject exceptions at arbitrary points | Yes: thread-locals, CurrentAttributes | [CVE-2022-23633](https://nvd.nist.gov/vuln/detail/CVE-2022-23633), [CVE-2022-23634](https://nvd.nist.gov/vuln/detail/CVE-2022-23634) (an unclosed body skips the executor reset) | Medium |
| **OpenResty / lua-nginx-module** | LuaJIT `LUA_ERRMEM` and `error()` from C API argument checks | Yes: module tables per worker; request-scoped objects must not be shared | No verified CVE in this class located | Medium |
| **Legacy persistent PHP SAPIs** (LSAPI, php-cgi FastCGI, uWSGI-php, NGINX Unit) | Same engine as PHP; startup/shutdown ordering is SAPI-specific | Yes | As for PHP | Medium (Unit has no maintainer) |
| **Perl** | `die` / `croak` through `JMPENV` `longjmp`; out of memory is fatal | mod_perl / FCGI | [CVE-2011-2766](https://nvd.nist.gov/vuln/detail/CVE-2011-2766) (one request's environment used in later requests), [CVE-2011-2767](https://nvd.nist.gov/vuln/detail/CVE-2011-2767) | Low–Medium |
| **Apache httpd / nginx** (C, pools) | Return-code errors; per-request pools | Scoreboard, session caches, upstream keepalive | [CVE-2019-0211](https://nvd.nist.gov/vuln/detail/CVE-2019-0211), [CVE-2022-22720](https://nvd.nist.gov/vuln/detail/CVE-2022-22720), [CVE-2021-44790](https://nvd.nist.gov/vuln/detail/CVE-2021-44790) (mod_lua), [CVE-2025-23419](https://nvd.nist.gov/vuln/detail/CVE-2025-23419) | Medium |
| **libpng / libjpeg / ImageMagick** | `setjmp` error handlers; ImageMagick policy resource limits | Embedder-dependent | [CVE-2019-7317](https://nvd.nist.gov/vuln/detail/CVE-2019-7317) (free callback runs inside `png_safe_execute`) | Medium |
| **SQLite** + bindings | `SQLITE_NOMEM` return codes; `sqlite3_soft_heap_limit64` / `sqlite3_hard_heap_limit64` | In-process caches | [CVE-2019-20218](https://nvd.nist.gov/vuln/detail/CVE-2019-20218), [CVE-2019-19926](https://nvd.nist.gov/vuln/detail/CVE-2019-19926) (error-path handling) | Low in core; Medium in bindings (`node:sqlite`, `bun:sqlite`) |
| **curl** | Return codes; state machines re-entered | Connection cache | [CVE-2023-38545](https://nvd.nist.gov/vuln/detail/CVE-2023-38545) (state lost across re-entry), [CVE-2021-22945](https://nvd.nist.gov/vuln/detail/CVE-2021-22945) | Low–Medium |
| **.NET / Kestrel** | `OutOfMemoryException` is catchable; stack overflow is not | Pooled `HttpContext` | [CVE-2024-38229](https://github.com/dotnet/aspnetcore/discussions/64485) (HTTP/3 use-after-free on stream close) | Low–Medium |
| **Node / Bun / Deno** | Engine out of memory is fatal; only RangeError-style size failures are recoverable (Node native code throws `ERR_MEMORY_ALLOCATION_FAILED` at 39 sites) [L] | Single process; pooled keep-alive sockets | Node [CVE-2026-105481](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) (stale keep-alive response) | Low (Node, Deno); Medium (Bun: Zig + pooling) |
| **Go / CPython / Tcl** | No recoverable out of memory in Go (panic/recover only); CPython uses return-based `MemoryError`; Tcl panics on allocation failure | Gunicorn / uWSGI, fasthttp context reuse, NaviServer | No verified CVE in this class located | Low |

### 3.2 Where variants are most plausible

These score highest on five factors: a non-local exit reachable without authentication, persistent state, C glue code, recent precedents, and an engine contract that just changed.

1. PHP out-of-tree runtimes and extensions
2. HAProxy Lua
3. Redis/Valkey Lua
4. PostgreSQL extensions
5. Java container recycling
6. Puma / Rails
7. OpenResty
8. Legacy PHP SAPIs

---

## 4. Defensive audit roadmap (grep patterns and discovery techniques)

**Discovery toolkit used across all targets:**
- **Fail-the-Nth-allocation sweeps:** iterate N from 1 to K over a regression test and look for crashes or leaks.
  - PHP: `USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1 ZEND_MM_MAX_ALLOCS=N` (in fixed releases).
  - Lua: `ltests` `T.alloccount` / `T.totalmem` and `testes/memerr.lua`.
  - CPython: `_testcapi.set_nomemory(start, stop)` [L].
  - SQLite: its out-of-memory test harness (`sqlite3_memdebug_fail`).
  - curl: `runtests.pl -t` (torture mode).
  - PostgreSQL 17+: `--enable-injection-points`.
  - Generic C: failmalloc via `LD_PRELOAD`, AFL++ libdislocator `AFL_LD_LIMIT_MB`, or sanitizer options `allocator_may_return_null=1` with `soft_rss_limit_mb` or `max_allocation_size_mb`.
- **libFuzzer `-malloc_limit_mb` / `-rss_limit_mb`:** these flag inputs that drive huge single allocations, i.e. where an attacker could reach a soft limit. They do not simulate failure; combine them with the sweep above.
- **Sanitizers:**
  - ASan for use-after-free
  - **MSan for CWE-824 uninitialized reads**
  - UBSan
  - Valgrind
  - glibc `MALLOC_PERTURB_`
  - PHP `USE_ZEND_ALLOC=0` so ASan sees Zend allocations
  - PostgreSQL `--enable-cassert`, which includes `CLOBBER_FREED_MEMORY`
- **Persistent-mode fuzzing with a state-diff oracle:** reuse one worker across inputs (libFuzzer in-process, or AFL++ `__AFL_LOOP` running one full request lifecycle per iteration, as php-src's `sapi/fuzzer` does).
  - After each input, send a fixed canary request.
  - Assert that the globals snapshot and the response match a clean baseline.

### Target-specific guidance

**Swoole/OpenSwoole and FrankenPHP worker loops**
- Grep:
  - `EG\((current_execute_data|vm_stack(_top|_end)?|exception|bailout|error_handling)\)\s*=` (coroutine save and restore)
  - `zend_is_unwind_exit|zend_is_graceful_exit|zend_throw_unwind_exit`
  - `ZEND_HAS_OOM|delayed_oom` (new API: is the runtime aware of it?)
  - `zend_try|zend_bailout`
- Check that an `UnwindExit` raised by out of memory inside a coroutine or worker iteration is told apart from a user `exit()`, and that executor globals are restored before shutdown.
- Inventory "last error" state that a worker loop must reset:
  - `rg -n "last_error|error_code|get_errors|ERR_get_error|errors\b" ext/`
  - Examples: openssl's error ring, json, pcre, intl, mbstring, iconv.

**PECL / APM extensions** (dd-trace-php, newrelic, opentelemetry, xdebug, blackfire, apcu, phpredis, imagick)
- Find module globals that hold pointers:
  - `rg -n "ZEND_BEGIN_MODULE_GLOBALS" -A40 | rg "\*|zval|HashTable"`
- Early consumers:
  - `rg -n "PHP_INI_MH\(|zend_error_cb\s*=|zend_observer_(error|fcall)_register|sapi_module\.\w+\s*="`
- Counters or flags changed around fallible calls:
  - `rg -n "(_G|EG|PG|BG)\(\w+\)\s*(\+\+|--|\+=|=\s*(1|true))"`
  - Confirm each is reset in RINIT, ideally an early RINIT equivalent, rather than only in RSHUTDOWN.
- Persistent-to-request pointers:
  - `rg -n "pemalloc\([^)]*,\s*1\)|zend_string_init\([^)]*,\s*1\)"`
  - Look for request-memory pointers stored inside these persistent structures.
- Run each extension's tests under the `ZEND_MM_MAX_ALLOCS` sweep on mod_php and FPM.

**HAProxy `hlua`**
- `rg -n "hlua_alloc|SET_SAFE_LJMP|RESET_SAFE_LJMP|lua_atpanic|luaL_error|lua_error" src/hlua*.c`
- In every C function exposed to Lua, look for stream, channel or HTX mutations (lengths, counters, flags) that happen before `lua_push*`, `lua_newtable`, `lua_setfield` or `luaL_Buffer` calls. All of these can raise `LUA_ERRMEM`.
- Testing: ASan build, tiny `tune.lua.maxmem`, `reg-tests/lua/*.vtc`, plus a local fail-the-Nth-allocation patch in `hlua_alloc`.

**Redis / Valkey**
- `rg -n "lua_push|lua_newtable|lua_rawseti|lua_settable|luaL_error|lua_checkstack" src/script_lua.c src/eval.c src/function_lua.c`
- Focus on reply-conversion functions and run-context flags such as `scriptRunCtx` or client flags set before conversion.
- Also review cross-client persistence: basic-type metatables, globals, and what `SCRIPT FLUSH` / `FUNCTION FLUSH` reset.
- Testing: `./runtest --single unit/scripting` under ASan, with a test-only failing `lua_Alloc` wrapper.

**PostgreSQL extensions**
- `rg -n "static\s+[^;=]*\*\s*\w+\s*=\s*NULL;"`, then trace assignments from `palloc`, `pstrdup`, `lappend` or `makeStringInfo` made while `CurrentMemoryContext` is query-lifetime.
- `rg -n "(nesting_level|depth|level)\s*(\+\+|--)"` inside `*_hook` wrappers that lack `PG_TRY` / `PG_FINALLY`. pg_stat_statements and auto_explain show the correct pattern.
- `rg -n "RegisterXactCallback|RegisterSubXactCallback|MemoryContextRegisterResetCallback"` to see which resets exist.
- Testing: cassert build, `debug_discard_caches=1`, injection points, Valgrind, SQLsmith / SQLancer.

**Brotli ports and copies**
- Run the marker check from §2.2.
- (Port-specific grep patterns withheld pending private vendor notification.)
- Differential fuzzing: run upstream `c/fuzz/decode_fuzzer.c` corpora through patched C 1.2.1 and through each port (cargo-fuzz, `go test -fuzz`). Report any input that C now rejects with `BLOCK_SWITCH` but a port accepts or panics on. This needs no hand-made trigger.

**Java containers**
- `rg -n "void recycle\("`: look for sequences where an exception in one step skips later resets (wrap each step in try/finally).
- `rg -n "\.release\(\)"` inside catch blocks: look for a double release on error paths.
- Netty: `ReferenceCountUtil.release` appearing in both `exceptionCaught` and `finally`.
- Testing: keep-alive pipelines that trip header or body limits followed by a canary request; Jazzer against one long-lived server; `-Dio.netty.leakDetection.level=paranoid`; Jetty's tracking buffer pool.

**Ruby / Puma / Rails**
- Middleware that skips `body.close`; `Thread.current[` and `IsolatedExecutionState` use.
- C extensions that call `rb_raise` after a partial init without `rb_ensure` / `rb_protect`.
- Testing: single-thread persistent server with a canary oracle; Rack::Timeout / `Thread#raise` injection; `GC.stress`; failmalloc.

---

## 5. Top 8 (product, subsystem) targets for a variant hunt

| # | Target | Why it ranks here | Disclosure route |
|---|---|---|---|
| 1 | **Swoole / OpenSwoole: coroutine runtime and fatal-error handling** | The engine contract just changed (out of memory now unwinds; a hard limit calls `_exit`) while executor globals are swapped per coroutine. One persistent PHP "request" serves many HTTP requests. Classes (a) and (b) | swoole-src / openswoole GitHub security; php-src GHSA if the engine API is at fault |
| 2 | **FrankenPHP worker mode: per-extension request-scoped state** | Three 2026 advisories in this exact class. Many "last error" globals remain. The project treats these leaks as vulnerabilities. Also ZTS `_exit` availability impact | GitHub advisories on php/frankenphp |
| 3 | **PECL / APM extensions in mod_php / FPM** (dd-trace-php, newrelic, opentelemetry, xdebug, apcu, phpredis, imagick) | Module globals and early consumers (INI handlers, error and observer callbacks) fall outside the 402-file core fix. Now testable with `ZEND_MM_MAX_ALLOCS` | Each vendor's SECURITY.md or bug bounty |
| 4 | **HAProxy Lua (`hlua`) with `tune.lua.maxmem`** | Closest architectural twin of PHP2Shell: a soft cap, then an allocator that returns NULL, a `longjmp` through C glue, and the process continues with shared Lua state. Pre-auth if the Lua code touches request data | HAProxy security contact (see haproxy.org) |
| 5 | **Redis / Valkey Lua scripting** (`script_lua.c`, `function_lua.c`, vendored Lua 5.1 + cjson/cmsgpack) | One VM shared by all clients. Six Lua CVEs from 2021–2025, one of them a 13-year-old bug. Errors raised mid-conversion in C | Redis and Valkey SECURITY.md (GHSA for publication) |
| 6 | **PostgreSQL extension hooks** (pg_stat_monitor, pg_hint_plan, pgaudit, TimescaleDB, Citus, pgvector index builds, PostGIS) | `elog(ERROR)` `longjmp` with recoverable `palloc` failures and context resets is PHP's architecture. Statics pointing at query memory and unrestored counters are a known extension bug pattern | Extension maintainers; core issues to security@postgresql.org |
| 7 | **Brotli decoder copies and ports: CVE-2026-111497 scoping** (bundled copies in runtimes and proxies, plus Rust/Go ports) | Unpatched or same-logic copies are reachable through HTTP Content-Encoding. Time-sensitive. Specific status withheld pending private vendor notification | Vendor PSIRTs and crate maintainers |
| 8 | **Java container recycling under limit-triggered errors** (Tomcat `recycle()`, Jetty buffer pools, Undertow listeners, Netty pooled ByteBuf) | The densest precedent set for class (b), with cross-user data leaks. Error paths taken when limits trip are under-tested | security@tomcat.apache.org; Eclipse / Jetty GHSA; Netty GHSA; Red Hat (Undertow) |

**Next tier:**
- Puma / Rails executor (Puma GHSA, Rails HackerOne)
- OpenResty lua-nginx-module
- LSAPI / php-cgi / uWSGI PHP plugin (maintenance mode)
- NGINX Unit: archived, so coordinate with packagers
- `node:sqlite` / `bun:sqlite` out-of-memory paths in the bindings
- libxml2 thread-local error state in every persistent worker (no embargo process since 2025)

**Immediate defensive actions:**
- Update PHP to 8.2.35, 8.3.36, 8.4.27 or 8.5.12. Set `session.upload_progress.enabled=0` if unused [P].
- Update Node to 22.23.4, 24.22.1 or 26.12.1 [P].
- Upgrade PyPI `Brotli` / `brotlicffi` to 1.2.1.
- Patch system libbrotli (the lab's curl links the unpatched one) [L].
- Track bundled-brotli consumers for fixes.
- Do not rely on `process.versions.brotli` in scanners.

---

## Sources

**Node**
- [Node.js security releases, 2026-10-21](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- Node `doc/changelogs/CHANGELOG_V26.md` and `SECURITY.md` at v26.12.1 [L]
- Coverage: [CloudLinux](https://blog.cloudlinux.com/node-js-october-2026-security-releases), [Convika](https://convika.com/blog/nodejs-security-release-2026-10-brotli/), [Wardio](https://wardio.net/guides/nodejs-brotli-cve-2026-111497/)

**Brotli**
- [google/brotli commit 0ed4268](https://github.com/google/brotli/commit/0ed4268a4401abcb44720963)
- Tags v1.2.1 / v1.1.1 / v1.0.10, `CHANGELOG.md` and `SECURITY.md` [L]
- (Downstream source references withheld pending private vendor notification.)

**PHP**
- [GHSA-w8hw-w9fx-j79w / CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- php-src commit 506e87f at tag php-8.4.27 [L]
- Coverage: [Zscaler](https://www.zscaler.com/blogs/security-research/cve-2026-109618-and-cve-2026-109619-php-vulnerable-unauthenticated-rce), [Heise](https://www.heise.de/en/news/php2shell-Critical-flaws-allow-code-injection-in-PHP-11494897.html)
- [FrankenPHP security advisories](https://github.com/php/frankenphp/security), [GHSA-r3xh-3r3w-47gp](https://github.com/advisories/GHSA-r3xh-3r3w-47gp), [GHSA-v3ph-cgqh-r8p5](https://github.com/advisories/GHSA-v3ph-cgqh-r8p5)

**Lua, HAProxy, Redis, Valkey**
- Lua git history (lua/lua) [L]
- [HAProxy `lua.txt`](https://www.haproxy.org/download/2.9/doc/lua.txt)
- [Redis CVE-2025-49844 advisory](https://redis.io/blog/security-advisory-cve-2025-49844/)
- [Valkey fixed versions (runZero)](https://www.runzero.com/blog/valkey/)

**Other projects**
- [PostgreSQL CVE-2024-10978](https://www.postgresql.org/support/security/CVE-2024-10978)
- [Puma CVE-2022-23634 (OSV)](https://osv.dev/vulnerability/CVE-2022-23634)
- [PHP-FPM CVE-2021-21703 write-up (Lexfo)](https://blog.lexfo.fr/php-fpm-local-root.html)
- [NGINX Unit (archived)](https://unit.nginx.org)
- [nginx October 2026 fixes (The Hacker News)](https://thehackernews.com/2026/10/nginx-fixes-5-flaws-including-possible.html)
- [c-ares CVE-2026-33630](https://security-tracker.debian.org/tracker/CVE-2026-33630)
- [libxml2 embargo policy change (LWN)](https://lwn.net/Articles/1025971)
- [Heroku on rack-timeout risks](https://devcenter.heroku.com/articles/h12-request-timeout-in-ruby-mri)
- [lua-nginx-module known issues](https://nginx-lua.readthedocs.io/en/latest/lua-nginx-module/known-issues/)

**Adoption data**
- [W3Techs: PHP](https://w3techs.com/technologies/details/pl-php)
- [W3Techs: web servers](https://w3techs.com/technologies/overview/web_server)
- [W3Techs: language history](https://w3techs.com/technologies/history_overview/programming_language)
- [Stack Overflow survey 2026: web frameworks](https://survey.stackoverflow.co/2026/technology/data/web-framework)

**CVE links** are given inline (NVD format) for every precedent cited.

**Network note:** several sites (sansec, imperva, php.net, w3techs, nginx.org, lua.org) failed DNS lookup through this session's proxy and hackerone.com was refused by it, so for those I relied on search-result summaries [S] or on upstream git [L].
