# S&P-100 Cloud-Native, IaC & CI Layer Hunt (2026-10-24)

Round 12A covers the open-source plumbing S&P 100 companies run their platforms on:
- Kubernetes secrets and workload-identity components from the major clouds;
- the clouds' storage (CSI) drivers;
- the HashiCorp stack (now IBM);
- CI runners and official CI building blocks;
- client-side Kubernetes tooling.

Five hunters each had an independent skeptic, and High findings went to a second judge. Everything ran in-process
or against fakes on loopback. No cluster, cloud API or CI service was contacted, and command-injection cases were
shown by recording argv or with inert markers.

> **Disclosure status:** 9 confirmed vulnerabilities (1 High per the second judge; 5 Medium / Moderate; 3 Low /
> Low-Medium), all **unpatched**. Counts are grouped by bug class, not by product, and details are embargoed until
> fixes ship.

## Results (aggregate)

| Class | Confirmed |
|---|---|
| **Argument / DSL injection in a widely embedded fetch library.** A security fix applied to one major version was never ported to the other (an **incomplete fix**), plus a sibling injection in a second protocol getter | 2 (1 High, 1 Medium) |
| **Bearer token re-attached on a cross-host redirect** in a ubiquitous API client, reachable through a server-side proxy path (a fix-sibling of an earlier CVE) | 1 (Medium) |
| **Writes through symlinked directories** during dependency resolution in a package/templating tool (overwrite outside the project) | 1 (Medium) |
| **Unvalidated user values reaching `mount(8)` argv** in a storage driver (option injection on a privileged node daemon) | 1 (Medium) |
| **Resolver denial of service**: an attacker-declared archive size allocated up front | 1 (Moderate) |
| **Incomplete fix of a 2026 mount-restriction CVE**: enforced on one container type but not on sidecars or workspaces | 1 (Low–Moderate) |
| **Node identity reachable by tenant-defined volumes** in a storage driver | 1 (Low-Medium) |
| **Path traversal from a chart name** in a templating tool's opt-in mode | 1 (Low) |

## Publishable negatives
- **Kubernetes secrets & workload identity:** Secrets Store CSI Driver v1.6.1 with the AWS 3.1.4, Azure v1.8.2 and
  GCP v1.18.0 providers, the Azure Workload Identity webhook v1.6.3, the EKS pod-identity webhook v0.6.19 and the EKS
  Pod Identity Agent v0.2.6 showed **no cross-namespace secret or identity access** under documented configuration.
  - Namespaces come from the admission request.
  - Tokens are bound to the requesting pod.
  - Object paths are validated.

  One hardening issue applies across several of them: file modes are not masked, on a tmpfs mounted without
  `nosuid`. It is being sent as a joint report.
- **CI building blocks:** the official toolkit's file-command delimiter handling and the runner's masking held in
  our tests. The remaining items are API-hardening notes.

## Takeaways
1. **Backport security fixes across major versions.** A v1/v2 split in a library means two code paths. Here the fix
   for a 2024 CVE family reached only one of them.
2. **Strip credentials on every cross-origin redirect.** That includes API clients whose redirects come through a
   proxy the server operates.
3. **Re-check restrictions on every container type.** A mount restriction enforced on steps but not on sidecars or
   workspace mounts is an incomplete fix.
4. **Put `--` before user-derived argv.** Before calling a VCS client, `mount` or a file-transfer client, validate the value and
   separate it with `--`; the bug class keeps coming back.
