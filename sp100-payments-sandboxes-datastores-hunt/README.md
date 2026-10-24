# S&P-100 Payments, Sandboxes, Data Stores & Mail Hunt (2026-10-24)

Round 12B covers open-source enterprise components from S&P 100 companies:
- official payment SDKs (request signing, field-level encryption, webhook verification);
- polyglot and template sandboxes, and a widely embedded metadata toolkit;
- data stores backed by large cloud vendors;
- workflow and continuous-delivery platforms from a major streaming company;
- email-address handling across mail libraries and identity stacks.

Five hunters each had an independent skeptic, and High findings went to a second judge. Everything ran locally
with self-generated keys and data, and a local SMTP sink and fake metadata server on loopback. No payment
gateway, mail server or cloud service was contacted.

> **Disclosure status:** 10 confirmed vulnerabilities (1 High, upheld by the second judge; 4 Medium; 5 Low /
> Low-Moderate), all **unpatched**. Counts are grouped by bug class, and details are embargoed until fixes ship.

## Results (aggregate)

| Class | Confirmed |
|---|---|
| **SSRF guard bypass via redirects**: a redirect check that skips `Location` values starting with `/` (protocol-relative URLs), plus a guard that only exists in a retry path | 2 (1 **High** in the default config, 1 Low-Moderate) |
| **Authenticated encryption that isn't authenticated**: an AES-GCM tag never verified on decrypt, and truncated GCM tags accepted | 2 (Medium, Low) |
| **In-memory data store crashes reachable by low-privilege users**: an out-of-bounds read in an ACL key check (an unported upstream fix) and a script-engine panic that ends the server (an **incomplete fix**), plus an uninterruptible long loop | 3 (2 Medium, 1 Low) |
| **Address truncation in an SMTP transport**: an address passes a domain check for one domain while mail goes to another. An **incomplete fix** of a 2025 CVE that only blocked CR/LF | 1 (Medium) |
| **Server-side rendering markup injection** via unescaped attribute names (a regression between SSR engine versions) | 1 (Low) |
| **Metadata parser allocation sized by untrusted 64-bit lengths** (an incomplete-fix sibling) | 1 (Low) |

## Publishable negatives
- **Payment SDKs:** request signing and webhook verification held in most of the official SDKs we tested. That
  includes several processor and payout SDKs, plus the OAuth1 signers, whose quirks only cause server-side
  rejection.
- **Polyglot sandbox:** the strictest sandbox policy levels held their documented guarantees in our tests. One
  hardening note concerns which filesystem configurations the validator accepts.
- **Workflow engine:** its document-access SSRF policy can be bypassed with redirects, but under that project's
  open-source threat model this is hardening.

## Takeaways
1. **Resolve, then validate.** A redirect validator must resolve `Location` against the request URL, then validate
   the absolute result. Skipping "relative-looking" values (`//host`, `/\host`) is a full SSRF bypass.
2. **Use the AEAD API that verifies.** Call `decrypt_and_verify` or the equivalent, and pin the tag length.
   Decrypting GCM without checking the tag gives CTR-mode malleability.
3. **Port upstream security fixes into forks.** Several of the data-store findings are fixes the upstream project
   shipped but the fork never ported.
4. **Validate characters, not just control characters.** An address-handling fix that only blocks CR/LF leaves
   the truncation of non-ASCII characters to their low byte, which yields a different domain.
