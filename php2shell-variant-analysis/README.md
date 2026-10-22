# PHP2Shell + "Where Else?" — Defensive Brief and Platform Variant Map (Oct 2026)

**PHP2Shell** is two critical PHP-core RCEs: **CVE-2026-109618** and **CVE-2026-109619**, CVSS v4 9.2,
unauthenticated, disclosed and patched 2026-10-21, with exploitation attempts seen before disclosure.

> **Scope: defense only.** These docs contain no exploitation mechanics: no payloads, sizes, memory
> layout or attack chains. If you run PHP, the action item is: **upgrade to 8.2.35 / 8.3.36 /
> 8.4.27 / 8.5.12 (or your vendor's backport) and restart every worker.**

| Doc | What |
|---|---|
| [`01-php2shell-defensive-brief.md`](01-php2shell-defensive-brief.md) | Bug classes in plain language, exposure by SAPI, fixed versions, distro/vendor/cloud status, timeline, interim mitigations and their caveats, detection guidance, a "verify you're patched" checklist |
| [`02-platform-landscape-and-variant-map.md`](02-platform-landscape-and-variant-map.md) | Which runtimes, servers and shared libraries are deployed like PHP/Node today; shared-dependency blast radius (incl. the Node Brotli CVE); which products share PHP2Shell's preconditions, with historical CVE precedents; audit roadmap; top-8 variant targets |

## The bug class in one paragraph
Both CVEs are **request-lifecycle state that isn't cleaned up correctly when a request dies abnormally.**
- **-109618:** a fatal error, such as hitting `memory_limit` during request startup, interrupts an update
  midway, and cleanup later trusts the half-built structure.
- **-109619:** worker-wide state that points into one request's memory survives into the **next request
  on the same worker**.

## "What else is built like this?" (summary of doc 02)
- **Same preconditions:** an error mechanism that jumps out of an operation midway (e.g. a soft memory
  limit) plus long-lived workers that reuse globals across requests.
- **Most plausible places for variants (ranked):**
  1. Out-of-tree PHP runtimes and extensions (Swoole/OpenSwoole, FrankenPHP worker mode, which already
     had 3 cross-request leak CVEs in 2026, and APM/PECL extensions)
  2. HAProxy Lua
  3. Redis/Valkey Lua
  4. PostgreSQL extensions
  5. Java container object recycling
  6. Puma/Rails
  7. OpenResty
  8. Legacy PHP SAPIs
- **Shared dependencies are the other blast radius.** The Node Brotli RCE (CVE-2026-111497) is an
  **upstream google/brotli** bug, so every product that bundles the C decoder needs its own update.
  Doc 02 §2.2 gives a source/binary marker check for whether a copy is fixed. Downstream status for
  specific products is withheld pending private vendor notification.
- **Node.js, Deno, Go and CPython** are low-plausibility for the PHP2Shell class: engine OOM is fatal,
  or errors are return-based. Their recent CVEs cluster in parsing and identity checks instead. See
  [`../runtime-variant-hunting/`](../runtime-variant-hunting/).

## Recommended defensive discovery technique
**Allocation fault-injection.** Fail the N-th allocation in a request, then run the next request on
the same worker under ASan. php-src's fix adds exactly such a hook (`ZEND_MM_MAX_ALLOCS`), and Lua's
`T.allocount` found the same class years ago. Pair it with persistent-mode fuzzing that reuses one
worker across inputs to catch cross-request stale state. Doc 02 §4 has per-target grep patterns and
test harness notes for maintainers.
