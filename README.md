# PHP2Shell Helper

A lightweight Linux security audit for **PHP2Shell** (**CVE-2026-109618** and **CVE-2026-109619**). It locates PHP runtimes, checks versions against the first upstream security fixes, reports instances needing attention, and offers optional emergency service containment after explicit confirmation.

## Fixed upstream PHP releases

| Branch | Fixed version |
| --- | --- |
| PHP 8.5 | 8.5.12 or later |
| PHP 8.4 | 8.4.27 or later |
| PHP 8.3 | 8.3.36 or later |
| PHP 8.2 | 8.2.35 or later |
| PHP 8.1 and older | Upgrade or verify an independently maintained vendor security backport |

See the [official PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5).

## Quick start

On a Linux server that you administer:

```bash
git clone https://github.com/scardotdev/php2shell-helper.git
cd php2shell-helper
sudo bash php2shell-audit.sh
```

Run the script **on each PHP host**. For containerized applications, run it on the container host with access to the Docker/Podman engine. It uses Bash and standard Linux tools; service containment uses systemd.

The audit itself collects local inventory without sending web requests or exploit traffic.

## What the audit does

- Finds PHP commands on `PATH` and in common system, hosting-panel, and alternative PHP locations.
- Reads `/proc` to inspect PHP processes **actually running**, instead of depending on `php -v` alone.
- Detects loaded Apache PHP modules, which cannot safely be assessed from the CLI PHP version.
- Queries running Docker and Podman containers for PHP versions.
- Shows installed PHP package versions to help check whether your OS vendor has backported patches.
- Lists web-serving systemd services that can be stopped if you select emergency containment.

### Understanding results

| Result | Meaning / action |
| --- | --- |
| `UPSTREAM-FIXED` | Reported PHP release meets the published fix threshold. |
| `BELOW-UPSTREAM-FIX` | Upgrade, or establish that the OS/vendor backported **both** CVE fixes. |
| `EOL-REVIEW` | Legacy release: upgrade or confirm a vendor-maintained backport. |
| `UNKNOWN` / `UNKNOWN-BRANCH` | Runtime needs manual inspection. |
| `INCOMPLETE` | A running process, Apache module, or container could not be version-verified. Investigate it rather than treating the host as clear. |

The audit deliberately reports a loaded Apache `mod_php` module for review when it cannot independently determine the module's patched build. That is more reliable than assuming a separate CLI PHP binary describes the web-serving runtime.

## Optional emergency containment

If the assessment needs action and the script finds running web-serving systemd services, it asks you to type **`STOP`**.

Entering `STOP` attempts to stop **all services listed in the containment section**. This can immediately interrupt every website on the host, including unrelated applications. The operation is not a patch and does not stop containers or upstream load balancers.

Press Enter or enter anything else to decline. In noninteractive execution, the script never makes containment changes.

## Patch and restore safely

1. Identify every PHP runtime serving web requests: PHP-FPM, Apache module, PHP-CGI, LiteSpeed, FrankenPHP, or a container image.
2. Check your Linux distribution or hosting vendor's security advisory for fixes to **both** vulnerabilities. Version strings can remain unchanged when vendors backport a fix.
3. Back up application files, databases, and PHP/web-server configuration. Capture relevant logs if you suspect compromise.
4. Install trusted fixed PHP packages or rebuild/redeploy with a patched PHP image. Confirm your repositories actually contain the security update.
5. Verify PHP extensions and application compatibility; validate configuration.
6. Restart **all PHP workers**, then verify the PHP version used to serve web requests.
7. Perform application smoke tests and restore normal access. Rerun the audit to confirm findings are resolved.

On Debian or Ubuntu, review `sudo apt update && apt list --upgradable` and use `sudo apt upgrade` only after identifying the fixed packages. On RHEL-family systems, check `sudo dnf check-update 'php*'` and install the vendor's PHP security update. For Docker, rebuild and redeploy the application image rather than upgrading only the host.

The PHP security team also lists temporary, partial exposure-reduction measures in its [advisory](https://www.php.net/archive/2026.php#2026-10-21-5). Updating is the complete remediation.

## Exit codes

- `0`: inventory completed with no below-threshold versions found, or requested stops completed (see output).
- `1`: review required, incomplete inventory, containment declined, or containment failed.
- `2`: insufficient privileges.

## Security

Only run this script on systems you own or are authorized to administer. Review any fetched security script before executing it as root. Reports contain local paths and service/container names; sanitize output before sharing publicly.

## References

- [PHP Security Team — October 21, 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)
- [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)

## License

No license has been assigned yet. The repository owner should add a license before inviting redistribution or contributions.
