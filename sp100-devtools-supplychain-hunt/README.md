# S&P-100 Developer Tools, Supply Chain, Sandboxes & ML Loaders Hunt (2026-10-23)

Round 11A covers open-source developer and supply-chain tooling that S&P 100 companies build or depend on:
- Git credential and URL handling across Git clients and libraries;
- package managers and dependency clients;
- container image layer extraction and OCI hook / device-injection code;
- JavaScript isolation sandboxes and expression evaluators;
- "safe" model-loading modes in ML frameworks.

Five hunters each had an independent skeptic, and High findings went to a second judge. Everything ran locally:
loopback git servers and registries, dummy credentials in throwaway home directories, and crafted layers and
models in a sandbox directory. Impact was shown only with inert markers.

> **Disclosure status:** 9 confirmed vulnerabilities (1 High and 2 Moderate, all upheld by the second judge;
> 6 Medium / Low-Moderate / Low), all **unpatched**. Counts are grouped by bug class, not by product, and
> details are embargoed until fixes ship.

## Results (aggregate)

| Class | Confirmed |
|---|---|
| **Credential-helper protocol injection / wrong-origin credential lookup** in Git libraries embedded in widely used developer tools. A crafted remote URL makes a stored credential for another host get sent, with no user code run. A sibling of the Git and "Clone2Leak" CVEs | 2 (Medium) |
| **Install-script gate bypasses** in a package manager's install-time script policy (identity check confused by lockfile values) | 2 (Moderate / Low-Moderate) |
| **Credentials forwarded to any host after a redirect** in a package-manager client | 1 (Low-Moderate) |
| **Layer-extraction containment**: a whiteout entry that deletes outside the unpack root; an extractor that disagrees with runtimes on duplicate entries (scanner evasion) | 2 (Moderate / Low) |
| **Expression-sandbox isolation**: built-ins of the host realm overwritten from inside expressions (legacy engine) | 1 (**High**, non-default engine) |
| **Model-loader path containment**: an external-data check that follows a hardlink out of the model directory (a fix-sibling of a 2026 CVE) | 1 (Low) |

## Publishable negatives
- A widely used Git large-file client, just released with four CVE fixes, holds for redirect cookie stripping,
  config-file filtering, submodule-URL newlines and ssh argument quoting.
- PyTorch `torch.load(weights_only=True)` has no code-execution path in our tests. Building tensors over
  uninitialized memory is outside its stated guarantee.
- The membrane-style JS isolation library we tested held its documented guarantee (one hardening note).
- Go's toolchain: the auth-header-on-redirect behaviour we found had already been ruled not a vulnerability by
  the Go team.

## Takeaways
1. **Line-based protocols need line-safe values.** Any code that writes `key=value` lines from URL-derived data
   must reject CR/LF/NUL after decoding, not before. Git fixed this years ago, and re-implementations keep
   missing it.
2. **A new security feature is a new attack surface.** A script policy is only as strong as the identity it keys
   on. Lockfile-controlled fields must not feed that identity.
3. **Containment checks must match runtime semantics exactly**: whiteouts, hardlinks, duplicate entries. Any
   divergence becomes a scanner-evasion or out-of-root write.
