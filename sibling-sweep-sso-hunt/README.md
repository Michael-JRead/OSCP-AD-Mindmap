# Sibling Sweeps + SAML/OIDC Hunt (2026-10-23)

Round 7. The most productive technique in earlier rounds was **fix-sibling analysis**: take a bug class we
had confirmed in one widely used implementation and replay it against every other implementation of the same
protocol. This round did that for six of our confirmed classes and added two new enterprise-SSO surfaces.
Nine hunters, each with an independent skeptic. Everything ran on 127.0.0.1 with locally generated keys and
certificates: no IdP, CA, ACME or OAuth provider was contacted.

> **Disclosure status:** 35 confirmed vulnerabilities (7 High, 8 Medium / Moderate, 20 Low / Low-Medium /
> Low-Moderate), all **unpatched**. That is 26 from the main pass plus 9 of 13 lower-ranked candidates confirmed
> in a second, independent verification pass. Details are embargoed and go to each project privately first, so
> affected projects are not named here.

## Results by class (aggregate)

| Sibling class (origin) | Implementations swept | Confirmed |
|---|---|---|
| QUIC resource exhaustion with ACKs withheld: CID-retirement floods, stream credit returned before state is freed (our OpenSSL QUIC findings) | 8 QUIC stacks (4 Go/Rust, 4 C) | 4 (Medium / Low-Moderate, remote memory DoS) in 2 stacks |
| ECH state, downgrade-sentinel and HRR handling (our OpenSSL ECH finding) | 4 ECH implementations | **0**: none has any of the three classes (one previously known client issue; two RFC 9849 conformance bugs) |
| ACME server data treated as trusted local data (our ACME-client finding) | 8+ ACME clients and integrations | 3 (1 **High**: a trust-boundary error on the issuance path that allows a root-owned file write, shown only with an inert marker) |
| CWE-338 in crypto libraries (our SM2-nonce finding) | ecosystem sweep, npm/PyPI/Go/Packagist | 9 (5 **High**): fixed or time-seeded ephemeral keys and nonces in SM2/ElGamal and JOSE libraries, allowing plaintext or private-key recovery |
| `__Host-`/`__Secure-` cookie-prefix bypass via server-side name normalization (our round-4 finding) | 33 framework configurations across Python, JS, Ruby, Rust, Bun and Deno | 13 (Moderate / Medium / Low-Medium / Low), including one root cause in a shared parsing dependency |
| Unbounded urlencoded form parsing (Tornado CVE-2026-82397 sibling) | same frameworks | 2 (1 **High** per precedent, 1 Moderate) |
| Cross-request state after response-finishing exceptions (our app-server finding) | 14 Python/Ruby app-server configurations | 3 (Low / Low-Moderate) |
| **NEW:** OAuth 2.0 / OIDC logic (PKCE ordering, redirect matching, assertion replay, ID-token validation) | 10 authorization servers and client libraries | 1 (Low); other strong hits were already public or documented |
| **NEW:** SAML SP signature verification | 6 SP libraries, 17 configurations | **0** (see below) |

## Publishable negatives

- **SAML signature wrapping is closed in today's maintained SP libraries.** We ran a 47-case corpus across
  17 configurations of @node-saml/node-saml 5.1.0 (+ xml-crypto 6.4.0), samlify 2.15.1, ruby-saml 1.18.1,
  crewjam/saml 0.5.1 (+ goxmldsig 1.6.1), gosaml2 0.12.0 and php-saml 4.3.2, producing 799 verdicts and
  **0 forged identities accepted**. The corpus covered:
  - canonicalization splits: comment, CDATA, character reference, DTD entity;
  - XSW families on both assertion-signed and response-signed messages;
  - ID-attribute tricks;
  - KeyInfo/key-trust confusion;
  - HMAC key confusion;
  - extra transforms;
  - namespace rebinding;
  - signature relocation;
  - duplicate attributes.

  The structural reason it is closed: most libraries now take identity from the *signed canonical bytes*, not
  the original document. The remaining issues were in **logout** (unsigned SLO requests), which are known or
  documented.
- **ECH:** none of the four implementations tested (Go crypto/tls, wolfSSL, rustls client, BoringSSL by code
  review) has the per-connection accumulation, downgrade-sentinel or cleartext-inner-after-HRR classes we found
  in OpenSSL.
- **Cookie delivery is real.** We checked ground truth in a real Chromium against a simulated sibling subdomain:
  - Real `__Host-`/`__Secure-` cookies are rejected.
  - Names starting with raw 0xA0/0x85/0xFF bytes are accepted without prefix rules, and so are
    percent-encoded names and values smuggled after a space or comma. The browser then sends all of these back
    verbatim.
  - `document.cookie` sends Unicode spaces as UTF-8.

  So any server that normalizes cookie names more aggressively than the browser has a practical prefix
  bypass.

## Takeaways
1. **Fix-sibling analysis keeps paying.** Six replayed classes produced 34 confirmed issues, several in
   implementations whose recent advisories fixed only part of the class.
2. **"Remote input becomes local trust" is the highest-severity pattern again.** The High ACME finding is the
   same trust-boundary error as last round's, in a different tool.
3. **Shared parsing dependencies spread one bug across many frameworks.** Fixing it in the shared dependency
   is the efficient route.
4. **The SAML wrapping era is ending** for maintained libraries. Verify that your SP library takes identity from
   the signed bytes, and pin current versions.
