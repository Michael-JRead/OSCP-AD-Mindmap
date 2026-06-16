---
title: "Start Here — OSCP AD Methodology"
tags:
  - ad-mindmap
  - methodology
  - oscp
---

# 🎯 Start Here — OSCP AD Methodology

> [!tip] How to use this vault
> This is the linear playbook. Work top-to-bottom; each step links into the
> matching box of the [[AD Mindmap]] for the full command tree. Check items off
> as you go. Boxes deeper than the core flow (ADCS, delegation, ACLs, SCCM,
> trusts) are pivots you reach for when the path to DA isn't obvious.

## 1. Recon — no credentials
➡️ Full tree: [[No Credentials]]

- [ ] Find the DC / domain name (DNS, SMB, LDAP, ports 88/389/445)
- [ ] Anonymous / guest SMB + LDAP enumeration
- [ ] Enumerate or brute users to build a username list
- [ ] Check for quick wins on hosts (see below)

## 2. Quick wins / known vulns
➡️ Full tree: [[Quick Compromise]]

- [ ] Scan for unauthenticated RCE (Zerologon, EternalBlue, web apps, etc.)
- [ ] Also revisit once authenticated → [[Known Vulnerabilities (Authenticated)]]

## 3. Get a username → get credentials
➡️ Full tree: [[Valid User (No Password)]]

- [ ] Password spray the user list (watch lockout policy)
- [ ] AS-REP roast accounts without preauth → crack the hash
- [ ] Poison & relay on the wire → [[Man In The Middle]]
- [ ] Crack any captured hashes → [[Crack Hash]]

## 4. Authenticated enumeration
➡️ Full tree: [[Valid Credentials]]

- [ ] Run BloodHound (collect with the lowest-priv account you have)
- [ ] Enumerate users, groups, shares, ACLs, delegation, GPOs
- [ ] Kerberoast SPN accounts → crack → [[Crack Hash]]
- [ ] Note ADCS / SCCM if present → [[ADCS]] / [[SCCM]]

## 5. Move laterally
➡️ Full tree: [[Lateral Movement]]

- [ ] Reuse creds / hashes / tickets (PtH, PtT, PtC) across hosts
- [ ] Spot where your user is local admin → get a shell

## 6. Escalate locally
➡️ Full tree: [[Low Access (Privilege Escalation)]]

- [ ] Enumerate the host (winPEAS, PrivescCheck)
- [ ] Abuse service accounts (SeImpersonate → Potato), UAC, exploits

## 7. Loot credentials as admin
➡️ Full tree: [[Admin Access]]

- [ ] Dump LSASS, SAM, LSA secrets, DPAPI
- [ ] Feed new creds/hashes back into step 4–5

## 8. Find the path to Domain Admin

- [ ] Abusable ACLs/ACEs (GenericAll, WriteDacl, DCSync) → [[ACLs & ACEs Permissions]]
- [ ] Kerberos delegation (unconstrained/constrained/RBCD) → [[Kerberos Delegation]]
- [ ] ADCS certificate abuse (ESC1–ESC15) → [[ADCS]]
- [ ] SCCM takeover → [[SCCM]]

## 9. Domain Admin
➡️ Full tree: [[Domain Admin]]

- [ ] Dump NTDS.dit (DCSync / secretsdump) for every hash
- [ ] Grab DPAPI backup keys

## 10. Cross trust boundaries / persist
➡️ Full tree: [[Trusts]]

- [ ] Hop child→parent / across trusts → [[Trusts]]
- [ ] Establish persistence if in scope → [[Persistence]]

---
See the full grid and pivot graph in [[AD Mindmap]].
