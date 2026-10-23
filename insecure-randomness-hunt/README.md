# Insecure Randomness & Default Secrets Hunt (2026-10-23)

Round 8. The question: *where are the "random" secrets that widely deployed software relies on actually
predictable?* We did this the legitimate way — by auditing the open-source software that services run and
proving predictability on our **own local instances** — never by trying to predict or crack tokens of live
third-party services, and never by scanning the internet for deployments using default keys.

Six hunters, each with an independent skeptic: frozen entropy (snapshots/AOT/images), runtime CSPRNG
fallbacks, security tokens in self-hosted platforms (Go/Node; Python/Ruby/Java), token/ID helper libraries,
and shipped default secret keys.

> **Disclosure status:** 13 confirmed vulnerabilities (1 High, 1 Medium-High, 5 Medium, 6 Low/Low-Moderate),
> all **unpatched**; details are embargoed and go to each project privately first. Project names are withheld
> here deliberately — for the default-secret findings, a public list would be a scanning target list.

## Results (aggregate)

| Class | Confirmed | What it means |
|---|---|---|
| **Shipped default secret keys** (official docker-compose / Helm / k8s manifests / `.env.example`) | 4 (1 High, 1 Medium-High, 1 Medium, 1 Low-Medium) | Session-signing or JWT keys with fixed values in the official deployment path, no startup refusal — any instance left at the default lets an attacker forge sessions (up to admin). Same class as Apache Superset CVE-2023-27524. |
| **Predictable security tokens** (password-reset, email-verification, API keys, share links, invites) | 7 (3 Medium, 4 Low/Low-Moderate) | Tokens from time-based IDs (ULID, xid, UUIDv1) or non-cryptographic PRNGs (Math.random / nanoid non-secure, MT19937) in widely deployed self-hosted platforms. |
| **Platform / library defaults** | 2 (Low-Moderate, Low) | A multipart boundary generator and a client tool's PKCE/state values drawn from a non-CSPRNG. |
| Hardening (not counted) | ~10 | Frozen hash secrets in pre-initialized Wasm components; build-time-seeded PRNGs in AOT images; userland ID pools captured by startup snapshots; documented insecure defaults; low-entropy codes behind public oracles. |

## Publishable negatives

- **Official container images are clean:** all **2,591** current Dockerfiles in the official Docker Library
  were audited at their exact commits — none generates a secret (SSH host keys, app secret keys, JWT secrets,
  TLS keys, passwords) at **build** time.
- **Compiled-binary toolchains are clean:** `bun build --compile` (incl. bytecode), `deno compile`, javy, and
  componentize-js (which fails closed by trapping RNG use during pre-initialization) do not freeze entropy;
  Node's core snapshot caches carry the CVE-2026-106074 fix.

## How to protect your own deployments (no embargo needed)
1. **Never deploy with a shipped secret.** Grep your compose/Helm/env files for `change`, `insecure`,
   `secret`, `mysecret`, `example`, `CHANGEME` and replace every signing/encryption key with fresh random bytes
   (`openssl rand -hex 32`). Rotating a signing key invalidates forged sessions.
2. **Treat time-ordered IDs as public.** ULID, KSUID, xid, Snowflake and UUIDv1/v6/v7 are identifiers, not
   secrets. Tokens that grant access need ≥128 bits from a CSPRNG (`crypto.randomBytes`, `secrets.token_urlsafe`,
   `SecureRandom`, `crypto/rand`).
3. **`Math.random`, Python `random`, Ruby `rand`, Go `math/rand`, `java.util.Random` are predictable** from
   observed outputs; any secret they produce should be assumed recoverable.
4. **Anything computed at build/snapshot time is shared by every instance** — keep key generation at first
   run, not in image builds or startup snapshots.
