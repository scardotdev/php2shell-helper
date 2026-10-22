# PHP2Shell Helper

A single-file, dependency-free Bash tool that finds PHP vulnerable to **PHP2Shell**
(**CVE-2026-109618** and **CVE-2026-109619**) on a Linux server and in its running
containers, then helps you respond:

1. **Mitigate**: apply PHP's recommended temporary settings to reduce exposure to the known attack paths.
2. **Contain**: take vulnerable services offline, after explaining exactly what that breaks.
3. **Patch**: show step-by-step upgrade guidance for *this* host, then verify the fix is actually running.

> **If you run PHP on the web, update now.** PHP2Shell allows unauthenticated remote code
> execution. Exploit details leaked before the fix was released, and exploitation attempts
> have been reported. Configuration changes only buy time: the fix is a patched PHP build
> **plus a restart of every PHP worker**.

## Quick start

On each Linux server that runs PHP (for containers, on the container host):

```bash
git clone https://github.com/scardotdev/php2shell-helper.git
cd php2shell-helper
less php2shell-helper.sh          # review it first: you are about to run it as root
sudo bash php2shell-helper.sh
```

Detection is read-only and makes no network requests. Nothing changes unless you choose
an action from the menu **and** confirm it. For fleets and automation, use report-only mode
and the [exit codes](#usage):

```bash
sudo bash php2shell-helper.sh --report
```

Run `bash php2shell-helper.sh --explain` (no root needed) for a plain-language summary.

---

## What is PHP2Shell?

PHP2Shell is the name for two critical bugs in the **core of PHP**. They were reported by
Wiz, Calif and OpenAI and fixed by the PHP security team on 21 October 2026. Both are rated
**CVSS 4.0 9.2 (Critical)**. Successful exploitation runs attacker code with the
privileges of the web server account.

| CVE | PHP name | What goes wrong |
| --- | --- | --- |
| [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | RCE via OOM corruption | When PHP runs out of memory it jumps out of the current code. If that happens while request data is only partly initialized, request cleanup later treats the invalid data as valid. Attackers trigger it with an oversized form or multipart POST. On Apache mod_php this happens **while the request body is parsed, before any application code runs**. |
| [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | RCE via stale global state | A fatal error, timeout or late warning can leave a worker's internal state pointing at memory that was already freed. The *next* request on the same worker reads it before initialization resets it (use-after-free). Confirmed paths: **session upload progress** (enabled by default; no `session_start()` needed), **`fatal_error_backtraces`** on PHP 8.5 (enabled by default), and invalid or deprecated per-request INI settings. |

Because the vulnerable code runs before your application does, logins, application
firewalls and "we don't accept uploads" do not protect you.

### Who is affected?

Every PHP installation that serves web requests ([PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5)):

| Way PHP runs | Risk per PHP's advisories |
| --- | --- |
| Apache **mod_php** | **Highest.** RCE demonstrated for both CVEs with default limits, before application code runs. |
| **PHP-FPM** (nginx, Apache proxy_fcgi, Caddy...) | RCE demonstrated for CVE-2026-109619 via session upload progress. CVE-2026-109618 is susceptible by source analysis. |
| **FrankenPHP** | Likely susceptible to application-independent attacks (behaves like mod_php). |
| **LiteSpeed / LSAPI**, **php-cgi** | Affected; application-specific exploits likely. |
| CLI only (cron, queue workers) | Not reachable over HTTP by itself, but it is the same vulnerable engine and package: update it too. |

**Fixed upstream releases:**

| Branch | Fixed in |
| --- | --- |
| PHP 8.5 | 8.5.12 |
| PHP 8.4 | 8.4.27 |
| PHP 8.3 | 8.3.36 |
| PHP 8.2 | 8.2.35 (8.2 reaches end of life on 31 Dec 2026) |
| PHP 8.1 and older | **No upstream release.** Use a vendor backport (see [upgrading](#3-upgrade-safely-the-real-fix)) or PHP's minimal source backports for [7.4](https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619), [8.0](https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619) and [8.1](https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619), then plan a move to a supported branch. Wiz reports versions back to PHP 5.4 are affected. |

Linux distributions usually **backport** the fix without changing the PHP version number:
Ubuntu 24.04's fixed build still reports `8.3.6`. Never judge by `php -v` alone. This tool
reads the package changelog to tell the two apart.

### Why act now?

- Technical details **leaked before the coordinated release**, and public proof-of-concept code exists.
- Datadog cites AWS reports of exploitation attempts **as early as 17 October**, and several security vendors report scanning and attempts in the wild. CISA had not observed exploitation when it published, and neither CVE was in the CISA KEV catalog as of 22 October. Expect that to change.
- [CISA](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching) advises patching immediately, internet-facing systems first, and taking PHP systems that cannot be patched (including PHP 8.1 and older) **offline** until they can be.
- PHP on the web is everywhere: WordPress, Drupal, Magento, Laravel, phpMyAdmin, control panels, appliances. You may run PHP without realizing it.

---

## What the tool does

### Detection (read-only)

- Finds PHP executables on `PATH` and in system, alternative and control-panel locations: Debian/Ubuntu, RHEL/Remi/SCL, cPanel EasyApache, CloudLinux alt-php, Plesk, DirectAdmin, LiteSpeed lsphp, FrankenPHP and `/opt` builds.
- Finds Apache PHP modules (`libphp*.so`) on disk and **inside running Apache processes**.
- Inspects **running processes** through `/proc`, so it reports what is actually serving requests, not just what is installed.
- Reads the PHP version embedded in each binary or module (falling back to `-v` only when that string is missing).
- Checks the owning **package's changelog** (dpkg or rpm) for *both* CVE IDs to recognize vendor backports.
- Flags workers still running code that was **replaced on disk**, i.e. patched but not restarted.
- Checks PHP inside **running Docker and Podman containers**, including distro-package backports.
- Shows the effective values of the mitigation settings for each PHP configuration (CLI, FPM, mod_php).
- Lists per-request and pool INI overrides worth reviewing: FPM pools, Apache `php_value`/`php_admin_*`, `.htaccess`, nginx/Caddy `PHP_VALUE`.
- Shows **possible signs of exploitation**: shells or download tools started by PHP workers, plus request-startup memory exhaustion and worker crashes in the usual error logs.

### Result statuses

| Status | Meaning | What to do |
| --- | --- | --- |
| `PATCHED` | Version is at or above the upstream fix. | Nothing, if no `RESTART-NEEDED` row exists for it. |
| `PATCHED-VENDOR` | Older version string, but the package changelog names **both** CVEs (vendor backport). | Nothing. |
| `VULNERABLE` | Supported branch below the fix with no backport evidence. | Patch now. Mitigate or take offline until then. |
| `VULNERABLE-EOL` | PHP 8.1 or older with no backport evidence. | Vendor backport or upgrade. Consider taking it offline. |
| `RESTART-NEEDED` | A running process still uses a binary or module that was replaced on disk. | Restart that service fully. **The fix is not active yet.** |
| `UNVERIFIED` | Could not be checked: unreadable process, no changelog in a slimmed image, pre-release build. | Verify manually. Treat as vulnerable until then. |

### Response menu

After detection, if anything needs attention and you are at a terminal:

```
[1] Apply temporary mitigations  (reduce exposure while you patch)
[2] Take vulnerable services offline  (stop the risk; sites go down)
[3] Show how to upgrade safely on this host  (the real fix)
[4] What is PHP2Shell and why act now?
[5] Re-run detection
```

Every action shows its consequences and asks for confirmation. Without a terminal, the tool
never changes anything.

---

## 1. Temporary mitigations

These come from [PHP's own advisory](https://www.php.net/archive/2026.php#2026-10-21-5). In
PHP's words, they "reduce exposure to specific attack paths but do not make an installation
safe".

| Setting | Blocks | Side effects | Tool applies it |
| --- | --- | --- | --- |
| `session.upload_progress.enabled = 0` | Confirmed session paths of CVE-2026-109619 | Session-based upload progress bars stop updating; uploads still work. PHP suggests keeping it off **even after patching** if unused. | Yes (recommended) |
| `fatal_error_backtraces = 0` (PHP 8.5) | Confirmed backtrace path of CVE-2026-109619 | Fatal errors lose backtraces. | Yes (recommended) |
| `memory_limit = -1`, enforced as `php_admin_value` | The predictable memory-limit failure used by the confirmed CVE-2026-109618 exploit | **Availability risk.** One request can use all memory; the kernel OOM killer may then kill unrelated services such as your database. Pair it with a memory limit that kills only a single worker. | Optional, asked separately |
| `post_max_size = 8M` (no uploads) or `32M` (uploads), `upload_max_filesize` below it | Reduces memory pressure during parsing | Larger uploads or very large forms fail. | Optional, asked separately |
| `max_input_nesting_level` lower than 64 | Reduces parser memory use | Deeply nested form fields fail. | No (manual) |
| `pm.max_requests = 1` (FPM) | Limits reuse of stale worker state | Large performance cost. | No (manual) |

How the tool applies them:

- Writes `zz-php2shell-mitigation.ini` into each PHP configuration scan directory it finds (for example `/etc/php/8.3/fpm/conf.d/`), so it loads last and is easy to see.
- If you opt into `memory_limit = -1`, it adds a clearly marked `php_admin_value[memory_limit] = -1` block to each FPM pool, plus an Apache `php_admin_value` snippet for mod_php. Applications then cannot lower it with `ini_set()`. Pools that already set `memory_limit` are left alone and reported.
- Tests the PHP-FPM and Apache configuration before and after, undoing its server changes if a test fails, then offers to reload the PHP services.
- Backs up every file it modifies under `/var/backups/php2shell-helper/` and records changes in `/var/lib/php2shell-helper/manifest`. `sudo bash php2shell-helper.sh --revert` removes everything, optionally keeping `session.upload_progress.enabled = 0`.

Rules from PHP's advisory to follow when applying settings yourself:

- Use `php.ini`, the FPM pool or server configuration that applies **before request parsing**. `ini_set()` and FPM `.user.ini` act too late.
- **Restart every worker** afterwards.
- **Hiding errors does not help.** `display_errors`, `log_errors`, `error_reporting` and `@` do not stop CVE-2026-109619.
- **Remove invalid, deprecated or unneeded per-request INI settings**: Apache `php_value`/`php_flag`/`php_admin_*`, `.htaccess`, nginx `fastcgi_param PHP_VALUE`/`PHP_ADMIN_VALUE`. A diagnostic from one of them, even a hidden deprecation, is a confirmed CVE-2026-109619 trigger. The tool lists the ones it finds.
- **Never use `RLIMIT_AS` / `RLIMIT_DATA`** (`ulimit -v`, `rlimit_*`) as a memory cap. They trigger the vulnerable allocation-failure path.
- Fix attacker-reachable fatal errors and execution timeouts (upload/import handlers, callbacks, cleanup code).

At the edge (WAF, reverse proxy, CDN), cap decoded request body size **including chunked
requests without `Content-Length`**, and cap the number of fields, multipart parts and headers
per part. If your sites never accept multipart forms, block them before they reach PHP.
Attackers already vary payloads to evade WAF signatures, so treat edge rules as a supplement.

**Containers** are not changed by host settings. Bake the settings into the image and redeploy:

```dockerfile
# php:* official images
RUN printf 'session.upload_progress.enabled = 0\nfatal_error_backtraces = 0\n' \
      > /usr/local/etc/php/conf.d/zz-php2shell-mitigation.ini
```

## 2. Taking services offline

Choosing this lists the running web/PHP systemd services (Apache, nginx, Caddy, LiteSpeed,
FrankenPHP, every PHP-FPM variant) and any containers with unpatched or unverified PHP. Each
entry says what stopping it does. Stopping only PHP-FPM, for example, keeps static content up
while PHP pages fail. You pick which to stop, then type `STOP` to confirm.

**Understand the implications first:**

- Every site and API served by the stopped service becomes unavailable immediately. In-flight requests and uploads are cut off, and webhooks, payment callbacks, cron jobs and integrations calling those sites fail.
- Load balancers may shift traffic to other nodes, which may also be vulnerable.
- It **fixes nothing** and does not persist. Enabled services start again on reboot, and panels, configuration management or orchestrators (compose restart policies, Kubernetes) may restart them sooner.
- It does not undo a compromise that already happened.

Less disruptive alternatives: restrict access to trusted IPs at the firewall or load balancer,
serve a static maintenance page, or block oversized/multipart POSTs at a WAF. The tool prints
the commands to bring services back once patched.

## 3. Upgrade safely (the real fix)

Menu option 3 prints tailored guidance for the detected distribution, control panel, and
third-party repositories (Sury/ondrej, Remi). In outline:

1. **Prepare.** Back up application files, databases and configuration, or take a snapshot. If you suspect compromise, preserve logs and a disk image first.
2. **Install fixed packages** from your vendor (tables below), rebuild container images from a fixed base, or build a fixed source release.
3. **Verify the package, not `php -v`.** Both CVE IDs should appear:
   ```bash
   zgrep -cE 'CVE-2026-10961[89]' /usr/share/doc/php*-common/changelog.Debian.gz   # Debian/Ubuntu
   rpm -qa 'php*' | xargs -n1 rpm -q --changelog | grep -E 'CVE-2026-10961[89]'    # RPM-based
   ```
4. **Restart every PHP worker** with a full restart, not a reload: `systemctl restart php*-fpm apache2` (`httpd` on RHEL), `pkill lsphp` for LiteSpeed, and restart queue workers, schedulers and long-running PHP daemons. Redeploy containers.
   > With mod_php, a graceful reload (`apachectl graceful`, `apachectl restart`, `systemctl reload`) can leave the **old** module loaded in Apache's parent process. We reproduced this on Ubuntu 24.04 while testing this tool. The tool reports it as `RESTART-NEEDED`.
5. **Re-run the tool.** Every runtime should read `PATCHED` or `PATCHED-VENDOR` with no `RESTART-NEEDED`. Then smoke-test your sites.
6. Optionally `--revert` the temporary mitigations. Keeping `session.upload_progress.enabled = 0` is recommended if you do not use it.

### Fixed vendor packages

Taken from the vendors' own advisories on 22 October 2026. Always check your vendor's current
advisory, because fixes keep landing.

**Ubuntu** ([USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1), [USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2)):

| Release | Package | Fixed version |
| --- | --- | --- |
| 26.10 | php8.5 | 8.5.9-0ubuntu2.1 |
| 26.04 LTS | php8.5 | 8.5.4-0ubuntu1.5 |
| 24.04 LTS | php8.3 | 8.3.6-0ubuntu0.24.04.13 |
| 22.04 LTS | php8.1 | 8.1.2-1ubuntu2.28 |
| 20.04 LTS (Ubuntu Pro) | php7.4 | 7.4.3-4ubuntu2.29+esm5 |
| 18.04 LTS (Ubuntu Pro) | php7.2 | 7.2.24-0ubuntu0.18.04.17+esm14 |
| 16.04 LTS (Pro, Legacy add-on) | php7.0 | 7.0.33-0ubuntu0.16.04.16+esm22 |
| 14.04 LTS (Pro, Legacy add-on) | php5 | 5.5.9+dfsg-1ubuntu4.29+esm18 |

**Debian** ([DSA-6574-1](https://lists.debian.org/debian-security-announce/2026/msg00489.html), [security tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618)):

| Release | Package | Fixed version |
| --- | --- | --- |
| 13 trixie | php8.4 | 8.4.27-1~deb13u1 (DSA-6574-1) |
| 12 bookworm | php8.2 | 8.2.35-1~deb12u1 (DLA-4848-1) |
| sid | php8.4 | 8.4.27-1 |
| forky (testing) | php8.4 | still listed as vulnerable on 22 Oct |

**AlmaLinux** ([announcement](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/)) has backports for every stream on 8, 9 and 10. They keep the
version number and add `.alma.1`, e.g. `php-8.3.33-1.el10_2.alma.1`. **Red Hat** rates the
issue Important and documents mitigations in bulletin [RHSB-2026-013](https://access.redhat.com/security/vulnerabilities/RHSB-2026-013).
Check its errata for your module stream (`dnf module list php`). Rocky and Oracle Linux follow
the RHEL errata.

**Other sources.** These are reports from third-party trackers, not yet confirmed on the vendors' own pages:

- cPanel EasyApache 4 has moved ea-php82–85 to the fixed releases, with backports for ea-php74/80/81.
- CloudLinux is rolling out alt-php fixes for 5.2–8.5. `yum --security` may not list them.
- Plesk's 7.4/8.0/8.1 builds dated 21 Oct carry the fix with unchanged version numbers.
- Sury (packages.sury.org / ondrej PPA) ships fixes for 5.6–8.5. Legacy branches keep their old version numbers.
- PHP warned that the Remi repository would not have same-day updates.

Verify all of these with the changelog check above.

**Containers.** Rebuild from `php:8.5.12`, `8.4.27`, `8.3.36` or `8.2.35` (or newer)
images, or a FrankenPHP release that bundles them, with `docker build --pull`, then
redeploy. No official images are maintained for 8.1 and older.

---

## Have I already been attacked?

The tool shows quick signals. They justify investigation, but none is proof either way:

- **A PHP worker spawning a shell, downloader or interpreter** (`sh`, `curl`, `wget`, `python`...) is the most direct evidence of exploitation. Some applications legitimately shell out (for example to `sendmail`), so read the command line.
- `Allowed memory size of ... exhausted ... in Unknown on line 0` in PHP or web-server error logs. "Unknown on line 0" means the failure happened during request startup, the CVE-2026-109618 pattern. On its own it does not prove an attack.
- Apache `exit signal Segmentation fault` or PHP-FPM `exited on signal 11 (SIGSEGV)`, which can come from failed exploit attempts.

Hunt further in web and WAF logs:

- Very large or malformed multipart or `application/x-www-form-urlencoded` POSTs to `.php` URLs. The public exploit uses a field name of roughly 3.5 MB.
- Control bytes in form data.
- Chunked requests without `Content-Length`.
- Repeated HTTP 500s, unexplained worker churn, oversized `PHPSESSID` cookies.
- New or modified files under web roots, and crontabs or SSH keys belonging to the web user.

PHP notes that the absence of log entries is **not** proof of safety. If anything looks
wrong, isolate the host, preserve evidence, and rotate secrets the web user could read
(database passwords, API keys, application secrets).

---

## Usage

```
sudo bash php2shell-helper.sh            # detect, then interactive response menu
sudo bash php2shell-helper.sh --report   # detect and report only, never prompt or change
sudo bash php2shell-helper.sh --revert   # remove mitigations this tool applied
bash php2shell-helper.sh --explain       # what PHP2Shell is (no root needed)
bash php2shell-helper.sh --help
```

| Exit code | Meaning |
| --- | --- |
| `0` | Every PHP runtime found is patched and none is running replaced code. |
| `1` | Action needed: vulnerable, restart-needed or unverified runtimes. |
| `2` | Usage error or not run as root. |
| `3` | No PHP runtime found. |

Set `NO_COLOR=1` to disable colors. Requirements: Linux, Bash 4+, and standard tools
(coreutils, grep, sed, awk, gzip, find). Optional: dpkg or rpm for backport detection,
systemd for service actions, Docker or Podman for container checks.

### Files the tool may write (only after you confirm)

| Path | Purpose |
| --- | --- |
| `<php conf.d>/zz-php2shell-mitigation.ini` | Mitigation settings |
| FPM pool files (marked `; >>> php2shell-helper` block) | `php_admin_value[memory_limit] = -1` (only if chosen) |
| `/etc/apache2/conf-available/php2shell-mitigation.conf` or `/etc/httpd/conf.d/zz-php2shell-mitigation.conf` | Apache `php_admin_value memory_limit -1` (only if chosen) |
| `/var/lib/php2shell-helper/manifest` | What to revert |
| `/var/backups/php2shell-helper/<timestamp>/` | Copies of modified files |

### Limitations

- It checks one host at a time. It does not see stopped containers, unused images, Kubernetes pods on other nodes, Windows, or managed hosting where you lack root. Scan images in your registry or CI separately.
- Backport detection needs the package changelog. Some control-panel packages may not name the CVEs, and slim container images strip changelogs. Those show as `VULNERABLE`/`UNVERIFIED`, so confirm with the vendor.
- Effective values come from `php.ini` and `conf.d`. FPM pool and per-directory overrides are listed for review rather than evaluated, and FrankenPHP configuration is not read.
- Service actions need systemd. Without it, the tool explains what to restart or stop.

## Contributing

Issues and pull requests are welcome, especially detection for more platforms, panels and
packaging formats. Keep it a single, dependency-free Bash file that passes `shellcheck`,
keep detection read-only, and keep every change behind an explicit confirmation.

## References

Primary sources:

- [PHP security advisory, 21 Oct 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GHSA-w8hw-w9fx-j79w / CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [GHSA-6wmf-4rv5-p3rp / CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- CVE records: [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618), [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619)
- oss-security announcements: [OOM corruption](https://www.openwall.com/lists/oss-security/2026/10/21/6), [stale global state](https://www.openwall.com/lists/oss-security/2026/10/21/7)
- [CISA alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
- Vendors: [Ubuntu USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618), [Red Hat](https://access.redhat.com/security/cve/cve-2026-109618), [AlmaLinux](https://almalinux.org/blog/2026-10-21-php2shell-cve-2026-109618-cve-2026-109619/)

Analysis:

- [Wiz (discoverers)](https://www.wiz.io/blog/php2shell-php-rce)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Rapid7](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/)

## Security and responsible use

Run this only on systems you own or are authorized to administer. It sends no exploit
traffic and makes no network requests. Reports contain hostnames, paths and container names,
so sanitize output before sharing it publicly.

## License

Public domain, under [the Unlicense](LICENSE). Use, copy, modify and redistribute it for any
purpose, with no conditions and no attribution required.
