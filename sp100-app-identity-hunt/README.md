# S&P-100 App & Identity Layer Hunt (2026-10-23)

Round 10A covers open-source software that S&P 100 companies build or depend on at the application and identity
layer:
- Spring (Broadcom);
- JS server-function serializers (siblings of the React2Shell class);
- webhook-signature validators in official SDKs from cloud, collaboration and payments vendors;
- cloud-SDK credential providers (AWS, Azure, Google);
- Keycloak with the Red Hat Java stack (Quarkus, Vert.x, Netty, Undertow);
- ASP.NET Core with Kestrel and YARP.

Six hunters each had an independent skeptic, and every High finding went to a **second judge** that tried to
refute it. Everything ran locally with self-generated keys and certificates and stub servers on loopback. No
vendor endpoint was contacted.

> **Disclosure status:** 7 confirmed vulnerabilities (2 High, both upheld by the second judge; 2 Moderate DoS;
> 3 Low), all **unpatched**. Details are embargoed and go to each vendor's security team privately first, so
> affected products are not named here.

## Results (aggregate)

| Track | Confirmed | Class |
|---|---|---|
| Webhook-signature SDKs | 3 (1 **High**, 2 Moderate) | an official validator checks a certificate URL with one URL parser and fetches it with another, so **forged signed messages are accepted** (the "check here, use there" class); unauthenticated JWT claims mutating process-global state and causing quadratic CPU during request routing |
| JS server-function serializers | 2 (1 **High**, 1 Low) | a reviver that turns a few bytes of JSON into a huge allocation (an OOM crash from a tiny body), plus a dev-only RPC endpoint with no origin check. |
| Cloud credential providers | 1 (Low) | an **incomplete fix** of an earlier path-validation CVE |
| Java/.NET frameworks & IdPs (Spring, Keycloak + Red Hat Java stack, ASP.NET Core / Kestrel / YARP) | 1 (Low, non-default) | a sender-constrained (DPoP) refresh-token check that runs only when a proof is present, allowing a downgrade to a bearer token; plus 4 hardening items |

## Publishable negatives

- **Keycloak 26.8.1**, which bundles Quarkus 3.40.1, Vert.x 4.5.34 and Netty 4.1.138:
  - 38 encoded, absolute-form and matrix-parameter request-targets behind a path-filtering proxy all failed to
    reach `/admin`.
  - redirect_uri authority, userinfo and port tricks are rejected.
  - 2026 fix-siblings hold.
- **ASP.NET Core 10.0.13 / YARP 2.3.0:**
  - Cookie names are strict tokens, so the `__Host-` prefix bypass class we found in many other frameworks
    is absent.
  - Multipart, `[FromForm]` and Blazor form limits hold.
  - HTTP/2 reset accounting is capped for both client and server resets (the MadeYouReset class).
  - Chunk-extension CR/LF is rejected.
  - YARP forwards paths faithfully across 30 encoding tricks.
- **Spring Security 7.1.2 / Boot 4.1.2 / Framework 7.0.10 / Cloud Gateway 5.0.4:** the fix-siblings of 2026's
  actuator, servlet-path and default-chain advisories hold. We read 111 spring.io advisories from 2024–2026.
- **Google auth libraries:** no URL allow-list is left to bypass, by design, and the executable-source gate
  holds.

## Takeaways
1. **Two URL parsers on one value is still the #1 bug class.** The High webhook finding is a textbook case: the
   validator parses with a legacy parser, the HTTP client parses with WHATWG, and percent-decoding in the host
   splits them. Parse once, then validate and fetch the same parsed object.
2. **Serializers need allocation budgets, not just depth limits.** Any reviver that passes attacker data to a
   constructor (typed arrays, `Array(n)`) needs an explicit size check.
3. **Sender-constraint checks must not be "only if present".** For DPoP, mTLS-bound tokens and similar, a
   missing proof must fail closed when the token is bound.
4. **Incomplete fixes keep appearing.** Re-test each fixed CVE against the other OS, encoding and code path.
