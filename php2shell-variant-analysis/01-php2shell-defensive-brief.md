# PHP2Shell (CVE-2026-109618 / CVE-2026-109619): defensive brief

*Prepared 2026-10-22. Scope is defense only. This brief contains no exploitation mechanics.*

> **Source note:** The page fetcher could not resolve DNS for any site from this environment, so I could not open the primary pages (php.net, the GitHub advisories, CISA). Everything below comes from search-engine summaries of the cited pages. Items marked **(secondary)** come from aggregator or blog sources and I have not checked them against the vendor's own page. Check php.net, the GitHub advisories and your vendor's notice before you act on specific package strings.

---

## 0. TL;DR

- PHP2Shell is two memory-safety bugs in **PHP core**, not in any application or framework. Both can give **unauthenticated remote code execution** on PHP installs that serve web requests.
- PHP rates both **CVSS v4.0 9.2**. Red Hat rates them *Important*: CVSS v3 8.1 on its page, which also cites NVD at 9.8.
- **Fixed upstream releases (2026-10-21):** **8.5.12, 8.4.27, 8.3.36, 8.2.35**. 7.4, 8.0 and 8.1 get source-only backports, with no official binaries.
- Details **leaked on 2026-10-20**, before coordinated disclosure. CISA and the FBI told organizations to patch immediately. **They were not in CISA KEV as of the morning of 2026-10-22.** Exploitation *attempts* are widely reported, but no confirmed successful compromise has been published.
- **The only complete fix is patching and then restarting every PHP worker.** The config toggles and WAF rules below only reduce exposure.

---

## 1. What the bugs are (conceptual only)

Both bugs come from the same family of problems: **request-lifecycle state that is not cleaned up correctly when a request dies abnormally.** PHP handles fatal errors, such as running out of memory, with an abrupt "bail out" of the current request. If that happens at the wrong moment, cleanup code and later requests can trust state that is no longer valid.

| CVE | Advisory title / class | Plain-language description |
|---|---|---|
| **CVE-2026-109618** | Memory corruption on a fatal error (out-of-memory) during request startup. The upstream fix commit is titled "Avoid state corruption via bailout". | A fatal error while the request is still being set up leaves an internal structure half-built. The cleanup code that runs afterwards treats it as complete and valid. |
| **CVE-2026-109619** | "RCE via stale global state" (GHSA-6wmf-4rv5-p3rp) | Worker-wide state that points into one request's memory survives after that request is torn down. A **later request on the same worker** then uses the stale reference. PHP's advisory also lists **memory disclosure** as a confirmed impact. |

GHSA IDs as reported (secondary, SOCRadar): CVE-2026-109618 → **GHSA-w8hw-w9fx-j79w**; CVE-2026-109619 → **GHSA-6wmf-4rv5-p3rp**.

Why it is reachable without login: both bugs sit in code that runs **before any application code executes**, while PHP is parsing and setting up the request. Patching or hardening the application (WordPress, Laravel, etc.) does not help.

**Credit** (per Sansec and Wiz): Ryan Austin (Calif), Wiz Research (Sagi Tzadik, Shir Tamari, Nir Ohfeld, Tomer Schwartz) and OpenAI. The finders worked independently and their reports overlapped. The name "PHP2Shell" comes from Wiz, not from PHP.

---

## 2. Exposure

### 2.1 Affected versions

- **Affected:** 8.5.0–8.5.11, 8.4.0–8.4.26, 8.3.0–8.3.35, 8.2.0–8.2.34, plus all EOL branches.
- How far back it goes is **disputed**. Google Cloud and others say "PHP 5.4 through 8.5.11". Other sources say PHP has not confirmed anything older than 7.4. The leaked post's claims (CVSS 10.0, "PHP 5+") do not match the official 9.2 rating.

### 2.2 SAPIs and deployment models

| Deployment | Status per sources |
|---|---|
| PHP-FPM (nginx/Apache/Caddy front ends) | Affected. Sources disagree on *which* bug path lands on FPM. Red Hat says FPM workers exit on early-initialization failures before they reach the corrupted structure (relevant to -109618). PHP reportedly confirmed the -109619 path against FPM. Treat FPM as vulnerable. |
| Apache mod_php (prefork) | Affected |
| php-cgi / FastCGI | Affected |
| LiteSpeed (lsphp) | Affected |
| FrankenPHP (classic and worker mode) | Affected or "likely susceptible". FrankenPHP 1.13.2 ships the fixed PHP. |
| Long-running servers (Laravel Octane, RoadRunner, Swoole) | Not covered by the advisories. "Not discussed" does not mean "not affected", so treat them as web-facing. A worker *reload* may keep the old engine; you need a full process restart. |
| PHP CLI / cron | Not covered by the advisories and not normally reachable over HTTP. It ships in the same packages, so upgrade it anyway. |

### 2.3 Default settings that matter

- **`session.upload_progress.enabled` is On by default.** The built-in default is `1`; I confirmed this on the lab's PHP 8.4.19 CLI. This feature is part of the demonstrated session-lifecycle path for -109619.
- `memory_limit` defaults to 128M and `post_max_size` to 8M. The fatal-error-at-startup class (-109618) involves the normal memory-limit behaviour, so stock configs are exposed.
- **Lab note:** the PHP CLI on the lab host is 8.4.19, which is older than 8.4.27 and inside the affected range. It is CLI-only, but it should be upgraded.

### 2.4 Distro, vendor and platform status

Snapshot as of 2026-10-21/22. Status is changing quickly.

| Vendor | Status |
|---|---|
| **php.net / windows.php.net** | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 source and Windows builds released. Source-only backports for 7.4 / 8.0 / 8.1, with no new Windows builds for those. |
| **Red Hat** | Bulletin **RHSB-2026-013** ("Request handling memory corruption – php", *Important*). Affects RHEL 8, 9 and 10 and OpenShift Dev Spaces 3. Errata include RHSA-2026:87070 and :87071 (RHEL 10), :87072 (RHEL 9 php:8.2), :87079 (RHEL 9 php:8.3), :87073 and :87080 (RHEL 8; :87080 is php:7.4), and :87151. Status is "Ongoing", so more streams will follow. |
| **AlmaLinux** | Patched packages from 2026-10-21, ahead of Red Hat. Backported to every PHP stream Alma ships, including streams past their RHEL AppStream EOL. Some sources say a few EL8 streams lagged. |
| **Rocky Linux** | Synced Red Hat errata. Sources disagree on whether `dnf updateinfo` lists them, so check the changelog. |
| **Debian** (secondary) | DSA-6574-1 for trixie (php8.4 `8.4.27-1~deb13u1`). DLA-4848-1 for bookworm LTS (php8.2 `8.2.35-1~deb12u1`). sid was reportedly still unfixed when checked. |
| **Ubuntu** (secondary) | USN-8948-1. The fix is backported without changing the upstream number; for example, 24.04 php8.3 is `8.3.6-0ubuntu0.24.04.13`. Ubuntu does not ship php8.2 or php8.4 itself. |
| **deb.sury.org** (secondary) | Fixed packages for 8.2–8.5, with reported legacy backports down to 5.6. One tracker showed **arm64 builds lagging amd64**. |
| **Alpine** | 3.24 fixed for php83, php84 and php85. Older branches are unclear. |
| **Amazon Linux 2023** | Package update tracked in amazonlinux/amazon-linux-2023 issue #1148. Check the AWS bulletin for timing. |
| **cPanel** (secondary) | EasyApache 4 release 25.91 (2026-10-21): ea-php82–85 on fixed upstream, with backports for ea-php74, 80 and 81. ea-php73 and older get no fix (vendors point to TuxCare ELS). |
| **CloudLinux** (secondary) | alt-php fixed builds reached CL7–9 stable at about 00:07 UTC on 2026-10-22. PHP Selector users need the alt-php update separately. Imunify360 ruleset 8.83 adds blocking. |
| **Plesk** (secondary) | PHP 8.2–8.5 builds released 2026-10-21. Panel and sw-engine hotfixes: 18.0.80 Update 11 and 18.0.81 Update 4. 8.0/8.1 and Windows builds were still pending. |
| **Docker official `php` images** (secondary) | Rebuilt. The floating tag `php:8.2-fpm` reportedly still pointed at 8.2.34 for a while, so pin the exact tag. There was a brief "no match for platform in manifest" glitch. **Docker Hardened Images lagged**, and a clean scan there does not prove the fix is present. The WordPress, Drupal and Joomla images were rebuilt. |
| **AWS** | Bulletin **2026-143-AWS**: AWS's own services are not impacted. Elastic Beanstalk PHP platform v4.13.12 shipped on 10-21, with a follow-on upstream-fix release targeted for 10-22. Running **Lightsail** instances cannot be patched in place, so build new ones from the updated blueprints. |
| **Google Cloud** | Google says it is not itself vulnerable. Updated base images are rolling out for App Engine Std/Flex, Cloud Run, Cloud Run functions and Cloud Functions for Firebase. Custom containers must be rebuilt. A developer-forum report shows App Engine Standard in europe-west1 **still serving pre-fix versions** at 18:08 UTC on 10-21, so check what you are actually served. |
| **Microsoft Azure** | Guidance is to upgrade VMs, containers, base images and runtimes. App Service built-in images reportedly patched on some channels (no full official statement found). |
| **Managed hosts** (secondary) | Pantheon: patched on 8.2–8.5. WP Engine: rollout complete. GoDaddy Managed WP and Flywheel: patched. Automattic (WP.com, VIP, Pressable): "protected". SiteGround: disabled the affected features as a mitigation. Kinsta, Liquid Web, Rocket.net: still rolling out as of 10-22. |
| **Palo Alto Networks** | Product impact page published at security.paloaltonetworks.com/CVE-2026-109618. |

---

## 3. Timeline and in-the-wild activity

| Date (UTC) | Event |
|---|---|
| 2026-08-01 / 08-11 | Calif finds the bugs and reports the first one to PHP (per Sansec). |
| 2026-08-19 / 08-24 | Wiz finds and reports independently (per Wiz). |
| 2026-09-21 | PHP begins the coordinated fix (per Wiz). |
| **2026-10-17** | **AWS honeypots see exploitation attempts**, four days before patches existed (per The Register, citing AWS). AWS advises reviewing logs back to this date. |
| 2026-10-20 | An anonymous post leaks the CVE IDs and claims (CVSS 10, disclosure on 10-22). Kevin Beaumont and watchTowr confirm the flaws are real. PHP announces an out-of-band release for 10-21. |
| 2026-10-21 03:02 | Cloudflare WAF protections go live on all plans, including Free. |
| 2026-10-21 ~13:35–14:00 | PHP releases 8.5.12, 8.4.27, 8.3.36 and 8.2.35. Sources disagree on the exact time. |
| 2026-10-21 | CISA alert ("Critical Vulnerabilities in PHP Require Immediate Patching"); FBI Cyber Division; Canadian Cyber Centre AL26-026; NCSC UK; CERT-EU 2026-018; AWS 2026-143-AWS; Google Cloud; Red Hat RHSB-2026-013; Azure WAF guidance. |
| 2026-10-21 | watchTowr reports in-the-wild attempts on its "Attacker Eye" honeypots and has **not observed a successful attempt**. Huntress had seen no exploitation on partner systems at first. Datadog reports multiple reports of active exploitation plus broad untargeted scanning. Patchstack sees mostly probing. |
| 2026-10-22 | Cloudflare's CEO reports thousands of attempts in the 10 hours before disclosure, rising to **millions**, with attackers adjusting payloads to get past the rules. AWS's CISO calls exploitation "broad". **Not in CISA KEV** as of the 2026.10.21 catalog (re-checked on the morning of 10-22). No public IOCs (hashes, IPs, domains) have been published. Public PoC code is reported to exist. |
| by 2026-10-28 | Azure Front Door WAF managed rule rollout is expected to complete. |

**Assessment:** attempts at internet scale are confirmed by several providers. Successful compromise of production systems has **not been publicly confirmed**. Treat any internet-facing unpatched PHP as likely to be targeted.

---

## 4. Interim mitigations and caveats

**The patch is the only complete fix.** PHP, CISA, AWS, Microsoft and Cloudflare all say this. If you cannot patch at once, CISA advises taking the affected systems offline until they are patched.

| Mitigation | What it narrows | Caveats |
|---|---|---|
| **`session.upload_progress.enabled = 0`**, set administratively, then **restart every worker**. This is PHP's official workaround in GHSA-6wmf-4rv5-p3rp. | Blocks the demonstrated session-lifecycle path for -109619. | PHP says it **does not mitigate the other lifecycle paths**. It must be set in php.ini, an FPM pool (`php_admin_value`) or server config. **`ini_set()` and `.user.ini` do not work**, because the setting must apply before request parsing. It breaks upload progress bars. PHP suggests leaving it off even after patching if you do not use it. |
| **Request-size and shape limits at the edge** (nginx `client_max_body_size`, Apache `LimitRequestBody`, load balancer or WAF body-size rules) plus tight `post_max_size`, `upload_max_filesize`, `max_file_uploads`, `max_input_vars`, `max_input_nesting_level`, `max_multipart_body_parts`. | Reduces exposure to the fatal-error-during-startup class (-109618). | Set each to the smallest value your app needs and test your upload flows. Some requests can get past PHP's own early size check, so **enforce the limit in front of PHP as well**. This does not address -109619. |
| **memory_limit changes** (some vendors suggested an admin-locked `-1`). | Removes one trigger for PHP's own out-of-memory bail-out. | It can exhaust the host, so pair it with a cgroup or container memory cap. Other allocation-failure sources can still reach the same failure class. **Revert after patching:** the fix adds `memory_hard_limit_percent` (a hard limit above `memory_limit`), and `-1` disables both. |
| **Aggressive worker recycling** (e.g. a low FPM `pm.max_requests`) and restarting workers. | A restart clears the in-memory state that -109619 depends on. | This is not a fix and it costs performance. Some third-party guides suggest it, but it is not in PHP's advisory text. |
| **WAF virtual patches.** **Cloudflare:** "Generic Rules – Anomalous Execution" 1–7, on by default including Free (paid plans should confirm the Managed Ruleset is set to *block*), plus a response-side rule. **AWS WAF:** a custom "PHP2Shell" rule and the CRS `SizeRestrictions_BODY` rule, per 2026-143-AWS. **Azure Front Door:** managed rule 99006001, plus custom rules. **Akamai:** ASE rule 3000991. **Fastly:** Next-Gen WAF templated virtual patch, which customers must apply. **Google Cloud Armor:** recommended managed rules. **Imperva**, **Imunify360 8.83**. | Blocks known exploit traffic. | Cloudflare saw **attackers change payloads to get around rules**. Vendors call these partial or temporary. The Cloudflare rule names do not mention PHP or the CVEs, so search by rule ID. |
| PHP 8.5 `fatal_error_backtraces = 0`. | Reportedly affects a -109619 path. | From third-party guides only. I could not confirm it in PHP's advisory text. |

---

## 5. Detection guidance (general)

**Hunt window:** start from **2026-10-17**, per AWS.

**PHP, FPM and web-server error logs**
- Worker crashes: `exited on signal 11 (SIGSEGV)`, `signal 6 (SIGABRT)`, `Segmentation fault`, `exit signal` in Apache logs. Treat **bursts of crashes that line up with `multipart/form-data` POSTs** to arbitrary PHP endpoints as high-priority.
- Clusters of memory-exhaustion fatals, `Maximum execution time` errors, early startup or config warnings and shutdown diagnostics on routes reachable without login (Datadog guidance).
- After patching, `exited with code 137` or "Hard memory limit … exhausted" is the new hard limit firing. That is normally a sign of the fix working or of a sizing problem, not of exploitation.
- To get usable worker context, enable FPM `catch_workers_output = yes` and `decorate_workers_output`. Debian's default pool has `catch_workers_output` off.

**HTTP access and WAF logs**
- Unusual numbers of multipart POSTs, especially ones carrying the session upload-progress form field (the name set by `session.upload_progress.name`), to endpoints that do not take uploads.
- The same source producing repeated 5xx or 502 responses.
- WAF hits on the vendor rule IDs listed in section 4.

**Process tree and EDR**
- A PHP worker parent (`php-fpm`, `php-cgi`, `lsphp`, `httpd`, `apache2`, `frankenphp`) starting a shell (`sh`, `bash`, `dash`), an interpreter (`python`, `perl`) or a network or download tool (`curl`, `wget`, `nc`).
- Command lines containing `/dev/tcp/`, `mkfifo` or `fsockopen`, and recon commands (`id`, `whoami`, `uname -a`) running as the web user.
- Mapped to MITRE ATT&CK T1059. Expect false positives from apps that legitimately shell out (for example sendmail or ImageMagick), so build an allowlist.

**Ready-made content**
- Datadog Workload Protection has out-of-the-box coverage for a PHP app executing a shell.
- Graylog published log and telemetry queries. Tanium, FortiCNAPP, Arctic Wolf and Armis published response and exposure guidance.
- Community Sigma and Falco drafts exist (a Medium post and a GitHub gist). They are **unvalidated against real exploits**, so tune them before use.
- Huntress said its Sigma and YARA rules would follow.

**Host and file integrity**
- New or modified `.php` files in web roots or upload folders, changed `.htaccess` or `.user.ini`, odd files in the session save path, new cron entries, and outbound connections from the PHP worker's user.

**Evidence handling:** restarting workers wipes in-memory evidence. Quickly collect logs, the process list and outbound connection state on hosts you suspect, but **do not delay patching** to do it.

---

## 6. How to verify you are patched

1. **Find every PHP runtime**, not just the one on PATH: `/usr/sbin/php-fpm*`, `/opt/cpanel/ea-php*/root/usr/bin/php`, `/opt/alt/php*/usr/bin/php`, `/opt/remi/*`, `/usr/local/bin/php`, LiteSpeed `lsphp`, FrankenPHP binaries, and the PHP inside each container image.
2. **Check versions.** Run `php -v` and `php-fpm8.x -v` (or `-i`) for each binary. Upstream builds must be **≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**. `php -v` often differs from what the web SAPI actually loads, so also check the version *served*, for example from an internal-only status page.
3. **For distro packages, check the changelog, not the version number.** Backports keep the old upstream number (Ubuntu 24.04 still shows 8.3.6).
   - Debian/Ubuntu: `apt changelog php8.3-fpm | grep -E 'CVE-2026-10961[89]'` and `apt-cache policy php8.3-fpm`
   - RHEL/Alma/Rocky: `rpm -q --changelog php-fpm | grep -E 'CVE-2026-10961[89]'`
   - Alpine: `apk info -v | grep php8`
   - cPanel: `for p in /opt/cpanel/ea-php*/root/usr/bin/php; do "$p" -v | head -1; done`
   - Plesk: `plesk bin php_handler --list`
   - Also check sury.org arm64 hosts separately.
4. **Restart, don't reload.** Restart PHP-FPM pools, Apache (for mod_php), LiteSpeed, FrankenPHP and Octane/RoadRunner/Swoole servers. Then confirm:
   - each worker started after the package install (`ps -o lstart,cmd -C php-fpm8.3`);
   - no process still maps a deleted old binary or library (`lsof 2>/dev/null | grep -E 'php|libphp' | grep '(deleted)'`).
5. **Containers.** Rebuild on a **pinned** fixed tag (e.g. `php:8.2.35-fpm`; do not trust floating `8.2-*` tags or hardened images until they publish a fixed tag), redeploy, then run `php -r 'echo PHP_VERSION, PHP_EOL;'` inside a *running* pod or container. A host update does not touch PHP inside an image.
6. **PaaS and managed hosts.** Confirm the runtime version actually served (App Engine, Elastic Beanstalk, Lightsail, App Service, managed WordPress hosts) instead of relying on "auto-patched" claims.
7. **After patching, clean up the interim changes.** Remove any temporary `memory_limit = -1`, review the new `memory_hard_limit_percent` behaviour, keep `session.upload_progress.enabled = 0` if you do not use it, and keep the WAF rules on.
8. **EOL branches (≤ 8.1).** Move to a supported branch, or apply a vendor or distro backport (Alma, Red Hat, cPanel, sury, TuxCare-type ELS). Treat unofficial community patches as unvetted.

---

## Sources

**Primary and official**
- CISA alert: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- CISA on X: https://x.com/CISACyber/status/2112947079458717969
- FBI Cyber Division on X: https://x.com/FBICyberDiv/status/2112921648252719420
- PHP advisory GHSA-6wmf-4rv5-p3rp ("RCE via stale global state"): https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- PHP fix commit "Avoid state corruption via bailout": https://github.com/php/php-src/commit/31c0ea7d7ff1d1fccb6492e52dab544011628065
- php-src issue on hard memory limit behaviour: https://github.com/php/php-src/issues/24492
- PHP 8 ChangeLog: https://www.php.net/ChangeLog-8.php
- PHP 8.4.27 release info: https://php.watch/versions/8.4/releases/8.4.27
- Canadian Centre for Cyber Security AL26-026: https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619
- NCSC UK: https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php
- CERT-EU 2026-018: https://cert.europa.eu/publications/security-advisories/2026-018/
- Red Hat RHSB-2026-013: https://access.redhat.com/security/vulnerabilities/RHSB-2026-013
- Red Hat CVE page: https://access.redhat.com/security/cve/cve-2026-109618
- Red Hat errata: https://access.redhat.com/errata/RHSA-2026:87080 and https://access.redhat.com/errata/RHSA-2026:87151
- AlmaLinux: https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/
- AWS bulletin 2026-143-AWS: https://aws.amazon.com/security/security-bulletins/2026-143-aws/
- AWS Lightsail: https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-update-php-security-vulnerabilities.html
- Amazon Linux 2023 issue #1148: https://github.com/amazonlinux/amazon-linux-2023/issues/1148
- Google Cloud: https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619
- Google Cloud security bulletins: https://docs.cloud.google.com/support/bulletins
- App Engine lag report: https://discuss.google.dev/t/app-engine-standard-php-runtimes-not-yet-serving-patched-versions-for-cve-2026-109618-cve-2026-109619/407032
- Microsoft Azure (upgrade guidance and WAF): https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623
- Microsoft Azure (custom rules): https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/azure-waf-custom-rules-for-php2shell-mitigation/4566684
- Cloudflare: https://blog.cloudflare.com/php-vulnerabilities-waf-protection/
- Fastly: https://www.fastly.com/blog/fastlys-proactive-protection-critical-php-rce-cve-2026-109618
- CloudLinux / Imunify360: https://blog.cloudlinux.com/php-cve-2026-109618-and-cve-2026-109619
- Palo Alto Networks: https://security.paloaltonetworks.com/CVE-2026-109618
- Fortinet FortiCNAPP: https://community.fortinet.com/forticnapp-63/technical-tip-how-does-forticnapp-protect-from-cve-2026-109618-cve-2026-109619-php-remote-code-execution-vulnerabilities-230741

**Research and threat intelligence**
- Wiz: https://www.wiz.io/blog/php2shell-php-rce
- Sansec: https://sansec.io/research/php2shell
- watchTowr (exploitation): https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/
- watchTowr (FAQ): https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
- Huntress: https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
- Datadog Security Labs: https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
- Tanium: https://www.tanium.com/blog/php2shell-responding-to-cve-2026-109618-and-cve-2026-109619
- Recorded Future: https://www.recordedfuture.com/blog/php2shell-vulnerability-exploitation
- Imperva: https://www.imperva.com/blog/php2shell-vulnerability-updates/
- Qualys: https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities
- Arctic Wolf: https://arcticwolf.com/resources/blog/arctic-wolf-labs-finding-prioritizing-and-patching-php2shell-exposure/
- Armis: https://www.armis.com/blog/php2shell-how-to-find-prioritize-and-patch-affected-systems/
- Graylog: https://graylog.org/post/detecting-php2shell-cves-with-graylog/
- Prophet Security: https://www.prophetsecurity.ai/blog/php2shell
- Patchstack: https://patchstack.com/articles/php-major-vulnerability-alert-10-2026/
- Upwind: https://www.upwind.io/feed/initial-assessment-php2shell-two-critical-unpatched-php-rces-cve-2026-109618-cve-2026-109619

**News (timeline and in-the-wild)**
- The Register (AWS: attacks began 10-17): https://www.theregister.com/cyber-crime/2026/10/22/hackers-pile-on-php2shell-as-aws-reveals-attacks-began-before-disclosure/5304749
- SecurityWeek: https://www.securityweek.com/php2shell-patches-land-as-first-exploitation-attempts-hit-sensors/ and https://www.securityweek.com/php2shell-mass-exploitation-looms-for-leaked-critical-php-flaws/
- The Hacker News: https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html and https://thehackernews.com/2026/10/php2shell-two-unpatched-critical-php.html
- BleepingComputer: https://www.bleepingcomputer.com/news/security/php-ships-emergency-patches-for-critical-php2shell-flaws/
- Help Net Security: https://www.helpnetsecurity.com/2026/10/21/php2shell-php-vulnerabilities-patched-cve-2026-109618-cve-2026-109619/
- Dark Reading: https://www.darkreading.com/application-security/php2shell-bugs-red-alert-security-industry
- The Defiant (Cloudflare CEO, millions of attempts): https://thedefiant.io/news/security/cloudflare-ceo-reports-millions-of-php2shell-exploit-attempts
- CybelAngel (timeline): https://cybelangel.com/blog/critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619/
- Rescana (KEV re-check on 10-22): https://www.rescana.com/post/php-rce-flaws-patch-october-2026-prepare-now

**Secondary (distro, panel, container and host status: verify before relying on them)**
- SOCRadar (GHSA mapping): https://socradar.io/blog/php2shell-cve-2026-109618-cve-2026-109619/
- cve.tools: https://cve.tools/blog/php2shell-cve-2026-109618-cve-2026-109619
- digitalapplied (fixes by distro and panel): https://www.digitalapplied.com/blog/php2shell-fixes-by-distro-control-panel-php-version
- computingforgeeks (Ubuntu): https://computingforgeeks.com/patch-php2shell-ubuntu/
- computingforgeeks (cPanel/WHM): https://computingforgeeks.com/patch-php2shell-cpanel-whm/
- computingforgeeks (mitigation without patching): https://computingforgeeks.com/php2shell-mitigation-without-patching/
- teramont: https://teramont.net/blog/php2shell-cve-2026-109618-109619-php-update
- linuxcompatible (sury.org): https://www.linuxcompatible.org/story/php2shell-patch-suryorg-ships-debian-ubuntu-updates-for-every-php-version-from-56-to-85/
- ma.ttias.be (patching): https://ma.ttias.be/php-cve-2026-109618-patch/
- ma.ttias.be (memory_hard_limit_percent): https://ma.ttias.be/php-memory-hard-limit/
- Docker on DEV: https://dev.to/docker/how-to-fix-php2shell-cve-2026-109618-and-cve-2026-109619-3df3
- safeguard.sh (Docker image rebuilds): https://safeguard.sh/resources/blog/php2shell-docker-php-images-rebuild-guide
- activeset (host status tracker): https://www.activeset.co/blog/php2shell-host-status
- securityonline (cPanel): https://securityonline.info/cpanel-php-update-php2shell-wp-toolkit/
- php2shell.uk FAQ: https://php2shell.uk/faq
- vulncheck: https://www.vulncheck.com/blog/php2shell-vulnerabilities
- Community detection gist (unvalidated): https://gist.github.com/Blevene/472692937d05145d29d17dc3c6edc2a0
- Medium Sigma outline (unvalidated): https://medium.com/@mathias.fuchs/brace-for-impact-php2shell-114912dedeb4