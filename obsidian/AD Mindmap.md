---
title: "AD Mindmap"
tags:
  - ad-mindmap
  - moc
---

# 🗺️ Active Directory Mindmap — v2025.03

> [!abstract] Map of Content
> Obsidian conversion of the [Orange Cyberdefense AD mindmap](https://orange-cyberdefense.github.io/ocd-mindmaps/). Each box below is its own note; the nested bullets inside each note are the foldable tree branches, and `➡️` arrows are `[[wikilinks]]` to the box the technique pivots into. Original write-up: https://mayfly277.github.io/posts/AD-mindmap-2k25/

## Attack flow (grid layout)

The columns follow the engagement progression, left to right: **No creds → Valid user → Authenticated → Low access → Delegation → Admin → Domain admin**.

| Col 1 | Col 2 | Col 3 | Col 4 | Col 5 | Col 6 | Col 7 |
| --- | --- | --- | --- | --- | --- | --- |
| 🔍 [[No Credentials]] | 👤 [[Valid User (No Password)]] | 🔑 [[Valid Credentials]] | 🪜 [[Low Access (Privilege Escalation)]] | 🎫 [[Kerberos Delegation]] | 🛡️ [[Admin Access]] | 👑 [[Domain Admin]] |
| 🍒 [[Quick Compromise]] | 📡 [[Man In The Middle]] |  | 🐛 [[Known Vulnerabilities (Authenticated)]] | 📜 [[ADCS]] | ↔️ [[Lateral Movement]] | 🤝 [[Trusts]] |
| ✍️ [[Authors]] | 🔓 [[Crack Hash]] |  | 🧬 [[ACLs & ACEs Permissions]] | 🗄️ [[SCCM]] |  | ♾️ [[Persistence]] |

## Pivot graph

```mermaid
flowchart LR
    mitm["Man In The Middle"]
    low_hanging["Quick Compromise"]
    know_vuln_auth["Known Vulnerabilities (Authenticated)"]
    acl["ACLs & ACEs Permissions"]
    admin["Admin Access"]
    crack_hash["Crack Hash"]
    no_creds["No Credentials"]
    lat_move["Lateral Movement"]
    persistence["Persistence"]
    trusts["Trusts"]
    authenticated["Valid Credentials"]
    adcs["ADCS"]
    sccm["SCCM"]
    authors["Authors"]
    dom_admin["Domain Admin"]
    low_access["Low Access (Privilege Escalation)"]
    valid_user["Valid User (No Password)"]
    delegation["Kerberos Delegation"]
    acl --> admin
    acl --> authenticated
    acl --> crack_hash
    acl --> delegation
    acl --> dom_admin
    acl --> lat_move
    adcs --> acl
    adcs --> dom_admin
    adcs --> lat_move
    admin --> acl
    admin --> authenticated
    admin --> crack_hash
    admin --> lat_move
    admin --> valid_user
    authenticated --> acl
    authenticated --> adcs
    authenticated --> crack_hash
    authenticated --> delegation
    authenticated --> lat_move
    authenticated --> low_hanging
    authenticated --> mitm
    authenticated --> sccm
    authenticated --> valid_user
    delegation --> admin
    delegation --> lat_move
    dom_admin --> authenticated
    dom_admin --> crack_hash
    dom_admin --> lat_move
    know_vuln_auth --> acl
    know_vuln_auth --> admin
    know_vuln_auth --> dom_admin
    know_vuln_auth --> lat_move
    know_vuln_auth --> mitm
    lat_move --> acl
    lat_move --> admin
    lat_move --> delegation
    lat_move --> low_access
    lat_move --> mitm
    lat_move --> trusts
    low_access --> admin
    low_access --> authenticated
    low_access --> mitm
    low_hanging --> admin
    low_hanging --> authenticated
    low_hanging --> dom_admin
    low_hanging --> low_access
    mitm --> acl
    mitm --> adcs
    mitm --> authenticated
    mitm --> crack_hash
    mitm --> delegation
    mitm --> dom_admin
    mitm --> lat_move
    mitm --> valid_user
    no_creds --> authenticated
    no_creds --> crack_hash
    no_creds --> low_hanging
    no_creds --> mitm
    no_creds --> valid_user
    sccm --> admin
    sccm --> authenticated
    sccm --> lat_move
    sccm --> mitm
    sccm --> no_creds
    trusts --> acl
    trusts --> adcs
    trusts --> delegation
    trusts --> lat_move
    valid_user --> authenticated
    valid_user --> crack_hash
    valid_user --> lat_move
```

## All boxes

- 🔍 [[No Credentials]]
- 👤 [[Valid User (No Password)]]
- 🔑 [[Valid Credentials]]
- 🪜 [[Low Access (Privilege Escalation)]]
- 🎫 [[Kerberos Delegation]]
- 🛡️ [[Admin Access]]
- 👑 [[Domain Admin]]
- 🍒 [[Quick Compromise]]
- 📡 [[Man In The Middle]]
- 🐛 [[Known Vulnerabilities (Authenticated)]]
- 📜 [[ADCS]]
- ↔️ [[Lateral Movement]]
- 🤝 [[Trusts]]
- 🔓 [[Crack Hash]]
- 🧬 [[ACLs & ACEs Permissions]]
- 🗄️ [[SCCM]]
- ♾️ [[Persistence]]
- ✍️ [[Authors]]
