# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-10-22

A rewrite. The audit script is replaced by `php2shell-helper.sh`, which detects
PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and then helps you mitigate,
contain and patch it.

### Added

- Interactive response menu after detection. Every action asks for an explicit
  confirmation, and nothing changes when run without a terminal:
  - **Temporary mitigations** from PHP's advisory:
    - `session.upload_progress.enabled = 0` and, on PHP 8.5,
      `fatal_error_backtraces = 0`, applied by default.
    - `memory_limit = -1` and a lower `post_max_size` (8M or 32M), offered
      separately with their trade-offs explained.
  - **Selective containment**: choose which systemd services or unpatched
    containers to stop, after the consequences are explained; confirm by typing
    `STOP`.
  - **Upgrade guidance** tailored to the detected distribution, control panel
    (cPanel, CloudLinux, Plesk, DirectAdmin) and repositories (Sury/ondrej,
    Remi), with fixed package versions from vendor advisories.
- `--revert` removes all applied mitigations. It can optionally keep
  `session.upload_progress.enabled = 0`, which PHP recommends keeping off even
  after patching if unused.
- `memory_limit = -1` is enforced through `php_admin_value` in FPM pools and in
  Apache, so applications cannot lower it again with `ini_set()`.
- Safety around configuration changes:
  - PHP-FPM and Apache configuration is tested before and after changes, and the
    tool refuses to change a configuration that already fails its own test.
  - Server changes are rolled back if a test fails.
  - Modified files are backed up to `/var/backups/php2shell-helper/`, and
    changes are recorded in `/var/lib/php2shell-helper/manifest`.
- Vendor backport detection: the owning package's dpkg or rpm changelog is
  checked for both CVE IDs (status `PATCHED-VENDOR`).
- `RESTART-NEEDED` status for PHP processes and Apache mod_php modules still
  running code that was replaced on disk, including after a graceful Apache
  reload.
- `UNVERIFIED` status for a distro package with no local changelog (for
  example, slim container images), showing the package version to compare
  against the vendor advisory.
- PHP version read from the version string embedded in binaries and modules,
  falling back to `-v`.
- Container checks now include distro-package backport evidence and package
  versions inside Docker and Podman containers.
- Effective mitigation settings shown per configuration context (CLI, PHP-FPM,
  Debian/Ubuntu mod_php).
- Review list of per-request and pool INI overrides: FPM pools, active Apache
  configuration, `.htaccess`, nginx/Caddy `PHP_VALUE`. Invalid or deprecated
  per-request settings are a confirmed CVE-2026-109619 trigger.
- Exploitation signals:
  - Shells and download tools started by PHP workers.
  - Request-startup memory exhaustion and worker crashes in common error logs.
- `--report`, `--explain`, `--version` and `--help` options; `NO_COLOR` support.
- Exit code `3` when no PHP runtime is found.
- More install locations: Remi, Red Hat Software Collections, CloudLinux
  alt-php PHP-FPM and lsphp, Plesk, DirectAdmin, php-cgi, and Apache module
  directories.
- More systemd units recognised: cPanel, Plesk, CloudLinux and Remi PHP-FPM
  units, FrankenPHP, and LiteSpeed (`lshttpd`).
- `LICENSE`: released into the public domain under the Unlicense.

### Changed

- **Breaking:** the script is renamed from `php2shell-audit.sh` to
  `php2shell-helper.sh`.
- **Breaking:** exit codes now mean `0` patched, `1` action needed, `2` usage or
  privilege error, `3` no PHP found.
- Result statuses are now `PATCHED`, `PATCHED-VENDOR`, `VULNERABLE`,
  `VULNERABLE-EOL`, `RESTART-NEEDED` and `UNVERIFIED`.
- Containment stops only the services and containers you select, instead of
  every listed web service at once.
- Pre-release builds of the exact fixed version (for example `8.5.12RC1`) are
  reported as `UNVERIFIED`, because release candidates predate the embargoed fix.
- The README is rewritten to cover:
  - what PHP2Shell is and which ways of running PHP are affected;
  - why to act now, mitigations and their side effects;
  - the implications of taking services offline;
  - safe upgrading with vendor fixed-package tables;
  - how to look for signs of compromise.

### Removed

- The installed-packages listing, replaced by per-runtime changelog evidence.

### Fixed

- Patched distribution builds that keep the old version number (for example
  Ubuntu 24.04's `8.3.6-0ubuntu0.24.04.13`) are no longer reported as vulnerable.
- Loaded Apache mod_php modules are no longer always flagged for review; their
  version and package are now checked.
- Workers running a replaced binary are reported as needing a restart instead
  of "unverifiable".
- Only real PHP executables are run from glob matches; tools such as `phpize`
  and `php-config` are skipped.
- Docker installed without a running daemon no longer counts as an incomplete
  inventory.

### Security

- Documents and acts on PHP's advisory guidance:
  - Do not rely on `ini_set()` or FPM `.user.ini` for mitigations.
  - Hiding errors does not help.
  - Never substitute `RLIMIT_AS` / `RLIMIT_DATA` for a memory limit.
  - Restart every worker after a change.
- The tool never injects per-request INI settings that could themselves emit
  diagnostics.

## [1.0.0] - 2026-10-22

### Added

- `php2shell-audit.sh`, a defensive inventory for PHP2Shell (CVE-2026-109618 /
  CVE-2026-109619):
  - PHP executables on `PATH` and in common system and hosting-panel locations.
  - Live PHP processes via `/proc`, and loaded Apache PHP modules.
  - PHP versions inside running Docker and Podman containers.
  - Installed PHP packages, listed for manual backport review.
  - Versions checked against the upstream fixes (8.5.12, 8.4.27, 8.3.36,
    8.2.35).
- Optional emergency containment: stop all detected web-serving systemd
  services after typing `STOP`.
- README with quick start, result meanings, containment warning, patch-and-restore
  steps and references.

[Unreleased]: https://github.com/scardotdev/php2shell-helper/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/scardotdev/php2shell-helper/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/scardotdev/php2shell-helper/releases/tag/v1.0.0
