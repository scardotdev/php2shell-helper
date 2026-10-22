#!/usr/bin/env bash
# php2shell-helper: detect PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and
# help mitigate, contain and patch it. Released into the public domain (Unlicense).
# https://github.com/scardotdev/php2shell-helper
set -o pipefail
export LC_ALL=C
shopt -s nullglob

readonly TOOL_VERSION=2.0.0
readonly ADVISORY='https://www.php.net/archive/2026.php#2026-10-21-5'
readonly GHSA_OOM='https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w'
readonly GHSA_STATE='https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp'
readonly MARK='php2shell-helper'
readonly DROPIN='zz-php2shell-mitigation.ini'
readonly STATE_DIR='/var/lib/php2shell-helper'
readonly MANIFEST="$STATE_DIR/manifest"
readonly BACKUP_ROOT='/var/backups/php2shell-helper'

if ((BASH_VERSINFO[0] < 4)); then echo 'php2shell-helper needs bash 4 or newer.' >&2; exit 2; fi

# ---------------------------------------------------------------- output ----
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  C_RED=$'\e[31m' C_GRN=$'\e[32m' C_YEL=$'\e[33m' C_BLD=$'\e[1m' C_DIM=$'\e[2m' C_OFF=$'\e[0m'
else
  C_RED='' C_GRN='' C_YEL='' C_BLD='' C_DIM='' C_OFF=''
fi
heading() { printf '\n%s== %s ==%s\n' "$C_BLD" "$1" "$C_OFF"; }
good() { printf '%s%s%s\n' "$C_GRN" "$*" "$C_OFF"; }
warn() { printf '%s%s%s\n' "$C_YEL" "$*" "$C_OFF"; }
bad() { printf '%s%s%s\n' "$C_RED" "$*" "$C_OFF"; }
dim() { printf '%s%s%s\n' "$C_DIM" "$*" "$C_OFF"; }
have() { command -v "$1" >/dev/null 2>&1; }
has_systemd() { [[ -d /run/systemd/system ]] && have systemctl; }

confirm() { # confirm "question" -> 0 only on an explicit yes
  local answer
  printf '%s [y/N]: ' "$1"
  IFS= read -r answer || return 1
  [[ $answer =~ ^[Yy]([Ee][Ss])?$ ]]
}

usage() {
  cat <<EOF
php2shell-helper $TOOL_VERSION: detect and respond to PHP2Shell (CVE-2026-109618, CVE-2026-109619)

Usage: sudo bash php2shell-helper.sh [option]

  (no option)   Detect, then offer an interactive menu to mitigate, take services
                offline, or get upgrade guidance. Nothing changes without confirmation.
  --report      Detect and report only; never prompt or change anything.
  --revert      Remove the temporary mitigations this tool applied.
  --explain     Explain what PHP2Shell is and why it matters (no root needed).
  --version     Print the version.
  -h, --help    Show this help.

Exit codes: 0 all runtimes patched, 1 action needed, 2 usage or privilege error,
            3 no PHP runtime found.
EOF
}

explain() {
  cat <<EOF
${C_BLD}What is PHP2Shell?${C_OFF}
PHP2Shell is the name for two critical bugs in the core of PHP itself, fixed on
21 October 2026. Each lets an unauthenticated attacker run code on the server with
the privileges of the web server account. Both are rated CVSS 4.0 9.2 (critical).

  CVE-2026-109618, "RCE via OOM corruption": when PHP runs out of memory while it is
    still parsing a request, it can leave request data half-initialized; cleanup then
    trusts that data. A single oversized form or multipart POST can trigger it. On
    Apache mod_php this happens before any application code runs, so login pages,
    WAF rules inside the app and "we don't accept uploads" do not help.
  CVE-2026-109619, "RCE via stale global state": after a fatal error or timeout, some
    state can survive into the next request on the same worker and point at freed
    memory. The confirmed paths use session upload progress (on by default, no
    session_start() needed) and, on PHP 8.5, fatal_error_backtraces (on by default).

${C_BLD}Who is affected?${C_OFF}
Every PHP that serves web requests: PHP-FPM, Apache mod_php (highest risk), php-cgi,
FrankenPHP and LiteSpeed. Fixed upstream in 8.5.12, 8.4.27, 8.3.36 and 8.2.35.
PHP 8.1 and older get no upstream release; only some vendors (Debian, Ubuntu Pro,
Red Hat, AlmaLinux, cPanel, CloudLinux, Sury, TuxCare...) ship backported fixes, often
WITHOUT changing the version number. That is why this tool checks package changelogs.

${C_BLD}Why act now?${C_OFF}
Technical details leaked before the coordinated release, public exploit code exists,
and exploitation attempts were seen from 17 October. Mass scanning is under way.
CISA advises patching immediately and taking unpatchable PHP systems offline.

${C_BLD}What fixes it?${C_OFF}
Only installing a fixed PHP build AND restarting every PHP worker. Configuration
changes reduce exposure to the known attack paths but, in PHP's words, "do not make an
installation safe". Containers must be rebuilt from a fixed image, not just restarted.

Advisory: $ADVISORY
          $GHSA_OOM
          $GHSA_STATE
EOF
}

# ------------------------------------------------------------- arguments ----
MODE=interactive
case ${1:-} in
  '') ;;
  --report) MODE=report ;;
  --revert) MODE=revert ;;
  --explain) explain; exit 0 ;;
  --version) echo "$TOOL_VERSION"; exit 0 ;;
  -h | --help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
if ((EUID != 0)); then echo 'Run as root: sudo bash php2shell-helper.sh' >&2; exit 2; fi

# ------------------------------------------------------------ inventory ----
# One row per runtime found: where it was seen, version, status, path, note.
declare -a R_WHERE=() R_VER=() R_STATUS=() R_PATH=() R_NOTE=()
declare -a HOST_BINS=()   # unique host PHP executables (for configuration checks)
declare -a CONTAINERS=()  # "engine id label" for containers with unpatched PHP
declare -A VISITED=() SEEN_MOD=() EVIDENCE_CACHE=()
HAVE_MODPHP=0

add_result() { R_WHERE+=("$1") R_VER+=("${2:-?}") R_STATUS+=("$3") R_PATH+=("$4") R_NOTE+=("${5:-}"); }

# Prints PATCHED, VULNERABLE, VULNERABLE-EOL or UNVERIFIED for a PHP version string.
version_status() {
  local major minor patch extra fix
  [[ $1 =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)([A-Za-z0-9]*) ]] || { echo UNVERIFIED; return; }
  major=$((10#${BASH_REMATCH[1]})) minor=$((10#${BASH_REMATCH[2]})) patch=$((10#${BASH_REMATCH[3]}))
  extra=${BASH_REMATCH[4]}
  if ((major < 8 || (major == 8 && minor < 2))); then echo VULNERABLE-EOL; return; fi
  case $major.$minor in
    8.2) fix=35 ;; 8.3) fix=36 ;; 8.4) fix=27 ;; 8.5) fix=12 ;;
    *) # Newer than every affected branch; early pre-releases may predate the fix.
      if [[ -n $extra ]]; then echo UNVERIFIED; else echo PATCHED; fi
      return ;;
  esac
  if ((patch < fix)); then echo VULNERABLE
  elif ((patch == fix)) && [[ -n $extra ]]; then echo UNVERIFIED # RCs predate the embargoed fix
  else echo PATCHED; fi
}

# PHP compiles "X-Powered-By: PHP/<version>" into the engine, so the version can be
# read from a binary or module without executing it. Falls back to running -v.
binary_version() {
  local file=$1 out
  out=$(grep -aoE -m1 'X-Powered-By: PHP/[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9]*' -- "$file" 2>/dev/null | head -n1)
  if [[ -z $out && $file != *.so ]]; then
    if [[ ${file##*/} == frankenphp* ]]; then
      out=$(timeout 5 "$file" version </dev/null 2>/dev/null | head -n1)
    else
      out=$(timeout 5 "$file" -v </dev/null 2>/dev/null | head -n1)
    fi
    out=${out/PHP /PHP/}
  fi
  [[ $out =~ PHP/([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9]*) ]] && printf '%s' "${BASH_REMATCH[1]}"
}

pkg_of() { # file -> owning package name, if any
  local out
  if have dpkg-query; then
    out=$(dpkg-query -S -- "$1" 2>/dev/null | head -n1) && [[ -n $out ]] && { printf '%s' "${out%%: *}"; return; }
  fi
  if have rpm; then
    out=$(rpm -qf --qf '%{NAME}\n' -- "$1" 2>/dev/null | head -n1) && [[ -n $out ]] && { printf '%s' "$out"; return; }
  fi
  return 1
}

pkg_version() {
  if have dpkg-query && dpkg-query -W -f='${Version}' -- "$1" 2>/dev/null; then return; fi
  have rpm && rpm -q --qf '%{VERSION}-%{RELEASE}' -- "$1" 2>/dev/null
}

changelog_text() { # package -> its changelog on stdout
  local pkg=${1%%:*} f found=1
  if have dpkg-query && dpkg-query -W -- "$1" >/dev/null 2>&1; then
    for f in /usr/share/doc/"$pkg"/changelog.Debian*.gz; do gzip -dc -- "$f" 2>/dev/null; found=0; done
    return $found
  fi
  have rpm && rpm -q --changelog -- "$1" 2>/dev/null
}

# Prints both, one, none or unknown: does the package changelog name both CVEs?
cve_evidence() {
  local pkg=$1 text n=0
  if [[ -z ${EVIDENCE_CACHE[$pkg]:-} ]]; then
    if ! text=$(changelog_text "$pkg") || [[ -z $text ]]; then
      EVIDENCE_CACHE[$pkg]=unknown
    else
      grep -q 'CVE-2026-109618' <<<"$text" && ((n += 1))
      grep -q 'CVE-2026-109619' <<<"$text" && ((n += 1))
      case $n in 2) EVIDENCE_CACHE[$pkg]=both ;; 1) EVIDENCE_CACHE[$pkg]=one ;; *) EVIDENCE_CACHE[$pkg]=none ;; esac
    fi
  fi
  printf '%s' "${EVIDENCE_CACHE[$pkg]}"
}

# Sets CL_STATUS / CL_NOTE for a file and its version, using vendor backport evidence.
classify() {
  local file=$1 ver=$2 pkg pver
  CL_STATUS=$(version_status "$ver") CL_NOTE=''
  [[ $CL_STATUS == PATCHED ]] && return
  if ! pkg=$(pkg_of "$file"); then
    CL_NOTE='not from a system package: version check only'
    return
  fi
  pver=$(pkg_version "$pkg")
  case $(cve_evidence "$pkg") in
    both) CL_STATUS=PATCHED-VENDOR CL_NOTE="$pkg $pver: vendor backport (changelog names both CVEs)" ;;
    one) CL_NOTE="$pkg $pver: changelog names only one of the two CVEs" ;;
    none) CL_NOTE="$pkg $pver: no PHP2Shell fix in package changelog" ;;
    *) CL_STATUS=UNVERIFIED CL_NOTE="$pkg $pver: no local changelog; compare this version with your vendor's advisory" ;;
  esac
}

mark_running() { # file where: label an already-listed runtime as live
  local idx=${VISITED[$1]:-}
  [[ -n $idx && $2 == pid:* && ${R_WHERE[$idx]} != pid:* ]] && R_WHERE[idx]="running $2"
  return 0
}

check_binary() { # file where
  local real ver
  real=$(readlink -f -- "$1" 2>/dev/null) || real=$1
  [[ -f $real && -x $real ]] || return 0
  if [[ -n ${VISITED[$real]:-} ]]; then mark_running "$real" "$2"; return 0; fi
  VISITED[$real]=${#R_STATUS[@]}
  ver=$(binary_version "$real")
  if [[ -z $ver ]]; then
    add_result "$2" '?' UNVERIFIED "$real" 'could not read a PHP version from this file'
    return
  fi
  classify "$real" "$ver"
  if [[ $CL_STATUS != PATCHED* && ${real##*/} =~ ^php[0-9.]*$ ]]; then
    CL_NOTE+="${CL_NOTE:+; }CLI binary: not reachable over HTTP itself, but it shares the vulnerable engine"
  fi
  add_result "$2" "$ver" "$CL_STATUS" "$real" "$CL_NOTE"
  HOST_BINS+=("$real")
}

check_module() { # module-file where [deleted]
  local lib=$1 ver
  HAVE_MODPHP=1
  # A replaced library is tracked separately from the file now on disk at that path.
  if [[ ${3:-} == deleted ]]; then
    [[ -z ${SEEN_MOD["$lib (deleted)"]:-} ]] || return 0
    SEEN_MOD["$lib (deleted)"]=${#R_STATUS[@]}
    add_result "$2" '?' RESTART-NEEDED "$lib" \
      'Apache still runs a mod_php that was replaced on disk; fully restart Apache (a graceful reload keeps the old module)'
    return
  fi
  if [[ -n ${SEEN_MOD[$lib]:-} ]]; then
    [[ $2 == pid:* && ${R_WHERE[${SEEN_MOD[$lib]}]} != *pid:* ]] && R_WHERE[${SEEN_MOD[$lib]}]="running $2"
    return 0
  fi
  SEEN_MOD[$lib]=${#R_STATUS[@]}
  ver=$(binary_version "$lib")
  classify "$lib" "$ver"
  add_result "$2" "$ver" "$CL_STATUS" "$lib" "$CL_NOTE"
}

is_php_name() { [[ $1 =~ ^(php([0-9.]+)?|php-cgi([0-9.]+)?|php-fpm([0-9.]+)?|php[0-9]+-(cgi|fpm)|lsphp([0-9]+)?|frankenphp)$ ]]; }

scan_host() {
  local exe path proc pid name target lib
  for exe in php php-cgi php-fpm lsphp frankenphp; do
    path=$(command -v "$exe" 2>/dev/null) && check_binary "$path" PATH
  done
  for path in /usr/bin/php* /usr/sbin/php-fpm* /usr/bin/php-cgi* /usr/lib/cgi-bin/php* \
    /usr/local/bin/php* /usr/local/sbin/php-fpm* /usr/local/bin/frankenphp \
    /opt/php*/bin/php /opt/php*/sbin/php-fpm /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
    /opt/rh/*php*/root/usr/bin/php /opt/rh/*php*/root/usr/sbin/php-fpm \
    /opt/alt/php*/usr/bin/php /opt/alt/php*/usr/sbin/php-fpm /opt/alt/php*/usr/bin/lsphp \
    /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
    /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm /usr/local/php*/bin/php /usr/local/php*/sbin/php-fpm* \
    /usr/local/lsws/lsphp*/bin/lsphp; do
    is_php_name "${path##*/}" && check_binary "$path" disk
  done
  for lib in /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so \
    /etc/httpd/modules/libphp*.so /usr/local/apache/modules/libphp*.so /usr/local/apache2/modules/libphp*.so; do
    check_module "$(readlink -f -- "$lib" 2>/dev/null || printf '%s' "$lib")" disk
  done

  # Live processes: what is actually serving requests right now.
  for proc in /proc/[0-9]*; do
    pid=${proc##*/}
    IFS= read -r name 2>/dev/null <"$proc/comm" || continue
    case $name in php* | lsphp* | frankenphp* | apache2 | httpd*) ;; *) continue ;; esac
    if [[ $name == apache2 || $name == httpd* ]]; then
      if [[ ! -r $proc/maps ]]; then
        [[ -n ${VISITED[apache-unreadable]:-} ]] || add_result "pid:$pid" '?' UNVERIFIED "$name" 'cannot read Apache memory maps'
        VISITED[apache-unreadable]=1
        continue
      fi
      while IFS= read -r lib; do
        if [[ $lib == *' (deleted)' ]]; then check_module "${lib% (deleted)}" "pid:$pid" deleted
        else check_module "$lib" "pid:$pid"; fi
      done < <(grep -oE '/[^ ]*/(libphp|mod_php)[^ /]*\.so( \(deleted\))?' "$proc/maps" 2>/dev/null | sort -u)
      continue
    fi
    target=$(readlink "$proc/exe" 2>/dev/null) || target=''
    if [[ -z $target ]]; then
      add_result "pid:$pid" '?' UNVERIFIED "$name" 'cannot inspect this PHP process'
    elif [[ $target == *' (deleted)' ]]; then
      [[ -z ${VISITED["deleted:$target"]:-} ]] || continue
      VISITED["deleted:$target"]=1
      add_result "pid:$pid" "$(binary_version "$proc/exe")" RESTART-NEEDED "${target% (deleted)}" \
        'still running a binary that was replaced on disk (upgraded?); restart this service'
    else
      check_binary "$target" "pid:$pid"
    fi
  done
}

# Runs inside each container: prints "path|version line|evidence|package version" per PHP binary.
# shellcheck disable=SC2016  # expanded by the container's shell, not this one
readonly CONTAINER_PROBE='
seen=" "
for x in php php-fpm php-cgi lsphp frankenphp /usr/sbin/php-fpm* /usr/local/sbin/php-fpm; do
  case $x in /*) p=$x ;; *) p=$(command -v "$x" 2>/dev/null) || continue ;; esac
  [ -x "$p" ] || continue
  r=$(readlink -f "$p" 2>/dev/null || echo "$p")
  case $seen in *" $r "*) continue ;; esac
  seen="$seen$r "
  if [ "${r##*/}" = frankenphp ]; then v=$("$r" version 2>/dev/null | head -n1); else v=$("$r" -v 2>/dev/null | head -n1); fi
  e=unknown c="" pv=""
  if command -v dpkg-query >/dev/null 2>&1; then
    k=$(dpkg-query -S "$r" 2>/dev/null | head -n1 | cut -d: -f1)
    if [ -n "$k" ]; then
      pv=$(dpkg-query -W -f="\${Package} \${Version}" "$k" 2>/dev/null)
      c=$(cat /usr/share/doc/"$k"/changelog.Debian*.gz 2>/dev/null | gzip -dc 2>/dev/null)
    fi
  elif command -v rpm >/dev/null 2>&1; then
    if k=$(rpm -qf --qf "%{NAME}" "$r" 2>/dev/null); then
      pv=$(rpm -q --qf "%{NAME} %{VERSION}-%{RELEASE}" "$k" 2>/dev/null)
      c=$(rpm -q --changelog "$k" 2>/dev/null)
    fi
  fi
  if [ -n "$c" ]; then
    n=0
    echo "$c" | grep -q CVE-2026-109618 && n=$((n+1))
    echo "$c" | grep -q CVE-2026-109619 && n=$((n+1))
    case $n in 2) e=both ;; 1) e=one ;; *) e=none ;; esac
  fi
  echo "$r|$v|$e|$pv"
done'

scan_containers() {
  local engine ids id label out path verline ev pv ver st note found flagged err
  for engine in docker podman; do
    have "$engine" || continue
    if ! ids=$(timeout 15 "$engine" ps -q 2>&1); then
      err=$ids
      if [[ $err =~ (daemon\ running|no\ such\ file|connection\ refused|failed\ to\ connect) ]]; then
        dim "  $engine is installed but its daemon is not running: no containers to check."
      else
        add_result "$engine" '?' UNVERIFIED '-' "could not list $engine containers: ${err:0:80}"
      fi
      continue
    fi
    for id in $ids; do
      label=$(timeout 10 "$engine" inspect --format '{{.Name}} ({{.Config.Image}})' "$id" 2>/dev/null) || label=$id
      label=${label#/}
      out=$(timeout 30 "$engine" exec "$id" sh -c "$CONTAINER_PROBE" 2>/dev/null) || out=''
      found=0 flagged=0
      while IFS='|' read -r path verline ev pv; do
        [[ $verline =~ PHP\ ([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9]*) ]] || continue
        found=1 ver=${BASH_REMATCH[1]} st=$(version_status "$ver") note="image: $label"
        if [[ $st != PATCHED && -n $pv ]]; then
          case $ev in
            both) st=PATCHED-VENDOR note="$note; $pv: vendor backport (changelog names both CVEs)" ;;
            one) note="$note; $pv: changelog names only one CVE" ;;
            none) note="$note; $pv: no PHP2Shell fix in package changelog" ;;
            *) st=UNVERIFIED note="$note; $pv: no changelog in image, compare with your vendor's advisory" ;;
          esac
        fi
        add_result "$engine:${id:0:12}" "$ver" "$st" "$path" "$note"
        [[ $st == PATCHED* || $flagged == 1 ]] || { CONTAINERS+=("$engine $id $label"); flagged=1; }
      done <<<"$out"
      ((found)) || dim "  $engine container without a detectable PHP binary: $label"
    done
  done
}

print_results() {
  local i st color
  heading 'PHP runtimes found'
  if ((${#R_STATUS[@]} == 0)); then
    warn 'No PHP runtime found on this host or in running containers.'
    return
  fi
  printf '%s%-20s %-13s %-15s %s%s\n' "$C_BLD" WHERE VERSION STATUS PATH "$C_OFF"
  for i in "${!R_STATUS[@]}"; do
    st=${R_STATUS[$i]}
    case $st in PATCHED*) color=$C_GRN ;; RESTART-NEEDED | UNVERIFIED) color=$C_YEL ;; *) color=$C_RED ;; esac
    printf '%-20s %-13s %s%-15s%s %s\n' "${R_WHERE[$i]}" "${R_VER[$i]}" "$color" "$st" "$C_OFF" "${R_PATH[$i]}"
    [[ -z ${R_NOTE[$i]} ]] || dim "                     ${R_NOTE[$i]}"
  done
}

# ------------------------------------------------------- configuration ----
# A configuration context is a way PHP is started with its own ini files.
declare -a CTX_LABEL=() CTX_INFO=() CTX_VER=()
declare -A SCAN_DIRS=()

normalize_info() { # phpinfo text or HTML -> "name => local => master" lines
  sed -E 's#</td><td class="v">#\t#g; s#<[^>]+>##g; s#\t# => #g'
}
ini_val() { awk -F' => ' -v k="$2" '{gsub(/^ +| +$/, "", $1)} $1 == k {print $2; exit}' <<<"$1"; }

collect_contexts() {
  local bin info dir ver cli
  CTX_LABEL=() CTX_INFO=() CTX_VER=() SCAN_DIRS=()
  for bin in "${HOST_BINS[@]}"; do
    [[ ${bin##*/} == frankenphp* ]] && continue
    info=$(timeout 10 "$bin" -i </dev/null 2>/dev/null | normalize_info)
    [[ $info == *'Loaded Configuration File'* ]] || continue
    CTX_LABEL+=("$bin") CTX_INFO+=("$info") CTX_VER+=("$(binary_version "$bin")")
    dir=$(ini_val "$info" 'Scan this dir for additional .ini files')
    [[ -d $dir ]] && SCAN_DIRS[$dir]=1
  done
  # Debian/Ubuntu mod_php has its own php.ini; evaluate it with the matching CLI.
  for dir in /etc/php/*/apache2; do
    ver=${dir#/etc/php/} ver=${ver%%/*} cli=/usr/bin/php$ver
    [[ -f $dir/php.ini && -x $cli ]] || continue
    [[ -e /usr/lib/apache2/modules/libphp$ver.so ]] || continue
    info=$(PHP_INI_SCAN_DIR=$dir/conf.d timeout 10 "$cli" -c "$dir/php.ini" -i </dev/null 2>/dev/null | normalize_info)
    [[ $info == *'Loaded Configuration File'* ]] || continue
    CTX_LABEL+=("mod_php $ver") CTX_INFO+=("$info") CTX_VER+=("$ver")
    [[ -d $dir/conf.d ]] && SCAN_DIRS[$dir/conf.d]=1
  done
  for dir in /etc/php/*/fpm/conf.d /etc/php/*/cgi/conf.d; do SCAN_DIRS[$dir]=1; done
}

size_bytes() { # "128M" -> bytes; -1 or empty -> -1
  local v=${1// /} n unit
  [[ $v =~ ^([0-9]+)([KkMmGg]?)$ ]] || { echo -1; return; }
  n=${BASH_REMATCH[1]} unit=${BASH_REMATCH[2]}
  case $unit in [Kk]) echo $((n * 1024)) ;; [Mm]) echo $((n * 1048576)) ;; [Gg]) echo $((n * 1073741824)) ;; *) echo "$n" ;; esac
}

print_config() {
  local i info up fb ml pm um nl ini
  heading 'Temporary-mitigation status (effective php.ini values)'
  if ((${#CTX_LABEL[@]} == 0)); then
    dim 'No host PHP configuration could be read.'
    return
  fi
  for i in "${!CTX_LABEL[@]}"; do
    info=${CTX_INFO[$i]}
    ini=$(ini_val "$info" 'Loaded Configuration File')
    up=$(ini_val "$info" session.upload_progress.enabled)
    fb=$(ini_val "$info" fatal_error_backtraces)
    ml=$(ini_val "$info" memory_limit)
    pm=$(ini_val "$info" post_max_size)
    um=$(ini_val "$info" upload_max_filesize)
    nl=$(ini_val "$info" max_input_nesting_level)
    printf '%s%s%s  %s[%s]%s\n' "$C_BLD" "${CTX_LABEL[$i]}" "$C_OFF" "$C_DIM" "${ini:-no php.ini}" "$C_OFF"
    if [[ $up =~ ^(On|1)$ ]]; then
      warn "    session.upload_progress.enabled = $up   (exposed: confirmed CVE-2026-109619 path)"
    else
      good "    session.upload_progress.enabled = ${up:-?}"
    fi
    if [[ -n $fb ]]; then
      if [[ $fb =~ ^(On|1)$ ]]; then warn "    fatal_error_backtraces = $fb   (exposed: confirmed PHP 8.5 path)"
      else good "    fatal_error_backtraces = $fb"; fi
    fi
    if [[ $ml == -1 ]]; then
      good "    memory_limit = -1"
    else
      printf '    memory_limit = %s   %s(finite: confirmed CVE-2026-109618 trigger; -1 is a trade-off)%s\n' "${ml:-?}" "$C_DIM" "$C_OFF"
    fi
    printf '    post_max_size = %s, upload_max_filesize = %s, max_input_nesting_level = %s\n' "${pm:-?}" "${um:-?}" "${nl:-?}"
    if (($(size_bytes "$pm") > 33554432)); then dim '    (post_max_size above 32M: PHP suggests 8M without uploads, 32M with)'; fi
  done
  dim 'Note: FPM pool php_admin_value/php_value settings are not shown above; see overrides below.'
}

# Per-request INI settings matter twice: they can undo mitigations, and an invalid or
# deprecated one is itself a confirmed CVE-2026-109619 trigger (mod_php, PHP_VALUE).
print_overrides() {
  local -a pools=() lines=()
  local f roots=() total=0
  heading 'Per-request and pool INI overrides to review'
  pools=(/etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf
    /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf /usr/local/etc/php-fpm.d/*.conf
    /opt/alt/php*/etc/php-fpm.d/*.conf /opt/plesk/php/*/etc/php-fpm.d/*.conf /usr/local/php*/etc/php-fpm.d/*.conf)
  if ((${#pools[@]})); then
    mapfile -t lines < <(grep -HnE '^[[:space:]]*php_(admin_)?(value|flag)\[(memory_limit|session\.upload_progress\.[a-z_]+|fatal_error_backtraces|post_max_size|upload_max_filesize|max_input_nesting_level)\]' "${pools[@]}" 2>/dev/null | grep -v "$MARK")
    for f in "${lines[@]}"; do echo "  FPM pool:  $f"; done
    total=$((total + ${#lines[@]}))
  fi
  # Active Apache configuration only; Debian's stock "php_admin_flag engine Off" is not a concern.
  mapfile -t lines < <(grep -RHnE '^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]' /etc/apache2/apache2.conf \
    /etc/apache2/conf-enabled /etc/apache2/mods-enabled /etc/apache2/sites-enabled /etc/httpd/conf /etc/httpd/conf.d \
    /etc/httpd/conf.modules.d /usr/local/apache/conf 2>/dev/null | grep -v "$MARK" |
    grep -vE 'php_admin_flag[[:space:]]+engine[[:space:]]' | head -n 40)
  for f in "${lines[@]}"; do echo "  Apache:    $f"; done
  total=$((total + ${#lines[@]}))
  mapfile -t lines < <(grep -rHnE 'PHP_(ADMIN_)?VALUE' /etc/nginx /usr/local/nginx/conf /etc/caddy 2>/dev/null | head -n 40)
  for f in "${lines[@]}"; do echo "  Frontend:  $f"; done
  total=$((total + ${#lines[@]}))
  for f in /var/www /srv /home/*/public_html /usr/share/nginx /var/www/vhosts; do [[ -d $f ]] && roots+=("$f"); done
  if ((${#roots[@]})); then
    mapfile -t lines < <(timeout 30 find "${roots[@]}" -maxdepth 6 -name .htaccess -size -1024k -print0 2>/dev/null |
      xargs -0r grep -HnE '^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]' 2>/dev/null | head -n 40)
    for f in "${lines[@]}"; do echo "  .htaccess: $f"; done
    total=$((total + ${#lines[@]}))
  fi
  ((total)) || good '  None found in pool, Apache, nginx/Caddy or .htaccess configuration.'
  cat <<'EOF'
  Why this matters: per-request settings (Apache php_value/php_flag/php_admin_*,
  .htaccess, nginx PHP_VALUE) are applied before PHP initializes each request. An
  invalid, obsolete or deprecated one there is a confirmed CVE-2026-109619 trigger,
  even if errors are hidden. Pool settings can also cancel a mitigation. Remove
  what you do not need; prefer php.ini or pool settings applied at startup.
EOF
}

print_signals() {
  local proc pid comm ppid pcomm rest user cmd log c1 c2 any=0
  heading 'Possible signs of exploitation (investigate; not proof either way)'
  for proc in /proc/[0-9]*; do
    pid=${proc##*/}
    IFS= read -r comm 2>/dev/null <"$proc/comm" || continue
    case $comm in sh | bash | dash | ash | zsh | ksh | csh | tcsh | nc | ncat | netcat | socat | curl | wget | python* | perl | ruby | busybox | telnet) ;; *) continue ;; esac
    IFS= read -r rest 2>/dev/null <"$proc/stat" || continue
    rest=${rest##*) } ppid=$(awk '{print $2}' <<<"$rest")
    IFS= read -r pcomm 2>/dev/null <"/proc/$ppid/comm" || continue
    case $pcomm in php-fpm* | php-cgi* | lsphp* | frankenphp* | apache2 | httpd*) ;; *) continue ;; esac
    user=$(stat -c %U "$proc" 2>/dev/null)
    cmd=$(tr '\0' ' ' <"$proc/cmdline" 2>/dev/null | cut -c1-160)
    warn "  $pcomm (pid $ppid) started $comm as $user: pid $pid: $cmd"
    any=1
  done
  ((any)) || good '  No shells or download tools running as children of PHP workers right now.'
  any=0
  for log in /var/log/apache2/*error*.log /var/log/httpd/*error_log /var/log/nginx/*error*.log /var/log/php*fpm*.log \
    /var/log/php-fpm/*.log /var/log/php*/*.log /usr/local/apache/logs/error_log /usr/local/lsws/logs/error.log; do
    [[ -f $log && -r $log ]] || continue
    c1=$(tail -n 50000 -- "$log" 2>/dev/null | grep -cE 'Allowed memory size of [0-9]+ bytes exhausted.* in Unknown on line 0')
    c2=$(tail -n 50000 -- "$log" 2>/dev/null | grep -cE 'exit signal Segmentation fault|signal 11 \(SIGSEGV')
    if ((c1 + c2 > 0)); then
      warn "  $log: $c1 memory exhaustion(s) during request startup, $c2 worker crash(es)"
      any=1
    fi
  done
  ((any)) || dim '  No request-startup memory exhaustion or worker crashes in the usual error logs.'
  dim '  Hunt further: oversized/malformed multipart or form POSTs to .php, repeated HTTP 500s,'
  dim '  worker churn, new files under web roots, web-user crontabs. See README for details.'
}

# ------------------------------------------------------------ assessment ----
ACTION_NEEDED=0
assess() {
  local st n_vuln=0 n_restart=0 n_unver=0
  for st in "${R_STATUS[@]}"; do
    case $st in VULNERABLE*) ((n_vuln += 1)) ;; RESTART-NEEDED) ((n_restart += 1)) ;; UNVERIFIED) ((n_unver += 1)) ;; esac
  done
  ACTION_NEEDED=$((n_vuln + n_restart + n_unver))
  heading 'Assessment'
  if ((${#R_STATUS[@]} == 0)); then
    echo 'No PHP found. If this host serves PHP from somewhere unusual, inspect it manually.'
    return
  fi
  if ((ACTION_NEEDED == 0)); then
    good 'All PHP runtimes found contain the PHP2Shell fixes and no worker is running replaced code.'
    [[ -s $MANIFEST ]] && dim "Temporary mitigations from this tool are still in place; remove them with --revert if you wish."
    return
  fi
  ((n_vuln)) && bad "VULNERABLE: $n_vuln runtime(s) lack the PHP2Shell fixes. Unauthenticated remote code execution is possible."
  ((n_restart)) && warn "RESTART NEEDED: $n_restart running PHP process(es) still use code that was replaced on disk. The fix is not active until they restart."
  ((n_unver)) && warn "UNVERIFIED: $n_unver runtime(s) could not be checked. Treat them as vulnerable until you confirm otherwise."
  echo 'Only a fixed PHP build plus a restart of every worker removes the risk.'
  echo "Advisory: $ADVISORY"
}

detect() {
  R_WHERE=() R_VER=() R_STATUS=() R_PATH=() R_NOTE=() HOST_BINS=() CONTAINERS=()
  VISITED=() SEEN_MOD=() HAVE_MODPHP=0
  printf '%sphp2shell-helper %s%s | %s | %s\n' "$C_BLD" "$TOOL_VERSION" "$C_OFF" "$(hostname 2>/dev/null)" "$(date -Is)"
  dim 'Checking for PHP2Shell (CVE-2026-109618, CVE-2026-109619). Read-only; nothing is sent anywhere.'
  scan_host
  scan_containers
  print_results
  collect_contexts
  print_config
  print_overrides
  print_signals
  assess
}

# ------------------------------------------------------------ mitigation ----
BACKUP_DIR=''
backup_file() { # copies a file once per run into the backup directory
  [[ -e $1 ]] || return 0
  [[ -n $BACKUP_DIR ]] || BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
  [[ -e $BACKUP_DIR$1 ]] && return 0
  mkdir -p -- "$BACKUP_DIR$(dirname -- "$1")" && cp -p -- "$1" "$BACKUP_DIR$1"
}
record() { mkdir -p "$STATE_DIR" && { grep -qxF -- "$1" "$MANIFEST" 2>/dev/null || echo "$1" >>"$MANIFEST"; }; }

fpm_pool_files() {
  printf '%s\n' /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /etc/opt/remi/php*/php-fpm.d/*.conf \
    /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf /usr/local/etc/php-fpm.d/*.conf /opt/alt/php*/etc/php-fpm.d/*.conf \
    /opt/plesk/php/*/etc/php-fpm.d/*.conf /usr/local/php*/etc/php-fpm.d/*.conf
}

apache_conf_path() {
  if [[ -d /etc/apache2/conf-available ]]; then echo /etc/apache2/conf-available/php2shell-mitigation.conf
  elif [[ -d /etc/httpd/conf.d ]]; then echo /etc/httpd/conf.d/zz-php2shell-mitigation.conf
  fi
}

validate_configs() { # 0 if every FPM and Apache config still parses
  local bin ok=0
  for bin in "${HOST_BINS[@]}"; do
    [[ ${bin##*/} == php-fpm* ]] || continue
    if ! timeout 20 "$bin" -t >/dev/null 2>&1; then bad "  Configuration test failed: $bin -t"; ok=1; fi
  done
  if ((HAVE_MODPHP)); then
    for bin in apache2ctl apachectl httpd; do
      have "$bin" || continue
      if ! timeout 20 "$bin" -t >/dev/null 2>&1; then bad "  Configuration test failed: $bin -t"; ok=1; fi
      break
    done
  fi
  return $ok
}

# Units that must restart for PHP configuration or code changes to take effect.
php_units() {
  has_systemd || return 0
  systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' |
    grep -E '^(php[0-9.]*-fpm|php-fpm|php[0-9]+-php-fpm|ea-php[0-9]+-php-fpm|plesk-php[0-9]+-fpm|alt-php[0-9]+-fpm|frankenphp)(@[^ ]+)?\.service$'
  ((HAVE_MODPHP)) && systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null |
    awk '{print $1}' | grep -E '^(apache2|httpd)\.service$'
  return 0
}

offer_reload() {
  local -a units=()
  local u failed=0
  mapfile -t units < <(php_units)
  echo
  echo 'PHP reads these settings only when its workers start. Every worker must restart.'
  if ((${#units[@]})); then
    printf '  %s\n' "${units[@]}"
    if confirm 'Gracefully reload these services now? (in-flight requests finish; brief latency)'; then
      for u in "${units[@]}"; do
        if systemctl reload-or-restart -- "$u"; then good "  Reloaded $u"; else bad "  FAILED: $u"; failed=1; fi
      done
    else
      echo "  Later, run: systemctl reload-or-restart ${units[*]}"
    fi
  else
    echo '  No PHP services found under systemd. Restart PHP-FPM / Apache / FrankenPHP yourself.'
  fi
  if pgrep -x lsphp >/dev/null 2>&1; then
    echo 'LiteSpeed: restarting the web server alone does not restart detached lsphp workers.'
    if confirm 'Terminate lsphp workers now so LiteSpeed respawns them with the new settings?'; then
      pkill -x lsphp && good '  lsphp workers terminated; LiteSpeed starts new ones on the next request.'
    fi
  fi
  ((${#CONTAINERS[@]})) && warn 'Containers are not changed by host settings: add the ini file to the image and redeploy (see README).'
  return $failed
}

write_dropin() { # dir content
  local f="$1/$DROPIN"
  backup_file "$f"
  printf '%s' "$2" >"$f" && chmod 0644 "$f" && record "dropin $f" && good "  wrote $f"
}

mitigate() {
  local -a dirs=() pools=() changed_pools=()
  local d f mem=0 post='' up_fix='' content conf block answer i bytes need_upload=0 apache_conf=''
  heading 'Apply temporary mitigations'
  cat <<EOF
These reduce exposure to the KNOWN attack paths. PHP is explicit that they "do not
make an installation safe": updating PHP is the only complete fix. Settings are
written as separate files so they are easy to review and remove (--revert).
EOF
  collect_contexts
  mapfile -t dirs < <(printf '%s\n' "${!SCAN_DIRS[@]}" | sort)
  if ((${#dirs[@]} == 0)); then
    warn 'No PHP configuration scan directory (conf.d) was found. Apply the settings in README by hand.'
    return 1
  fi
  echo
  echo "${C_BLD}Recommended, low risk${C_OFF} (written to these PHP configuration directories):"
  printf '    %s\n' "${dirs[@]}"
  cat <<'EOF'
  * session.upload_progress.enabled = 0   blocks the confirmed session paths of CVE-2026-109619.
      Side effect: upload progress bars that rely on PHP sessions stop updating. Uploads
      still work. PHP suggests keeping this off even after patching if you do not use it.
  * fatal_error_backtraces = 0            (PHP 8.5; older versions ignore it) blocks the
      confirmed backtrace path of CVE-2026-109619. Side effect: fatal errors lose backtraces.
EOF
  confirm 'Apply the recommended settings?' || { echo 'No changes made.'; return 1; }
  if ! validate_configs; then
    bad 'PHP-FPM or Apache configuration already fails its own test. Fix that first; no changes made.'
    return 1
  fi
  content="; $MARK: temporary PHP2Shell mitigation (CVE-2026-109618 / CVE-2026-109619)
; Created $(date -Is). This is NOT a fix: update PHP. Remove with: php2shell-helper.sh --revert
; $ADVISORY
session.upload_progress.enabled = 0
fatal_error_backtraces = 0
"
  echo
  echo "${C_BLD}Optional: memory_limit = -1${C_OFF} (CVE-2026-109618, primary configuration mitigation)"
  cat <<'EOF'
  Removes the predictable PHP memory-limit failure that the confirmed exploit relies on.
  TRADE-OFF: one request can then use all available memory. A runaway script or a
  denial-of-service request can push the host into the kernel OOM killer, which may kill
  unrelated services such as your database. Only choose this if the host has memory
  headroom or a cgroup/container memory limit that kills a single worker. Never use
  RLIMIT_AS / RLIMIT_DATA instead; they trigger the vulnerable path. It is enforced as
  php_admin_value (FPM pools, Apache) so applications cannot lower it with ini_set().
EOF
  if confirm 'Also set memory_limit = -1?'; then
    mem=1
    content+="memory_limit = -1
"
  fi
  echo
  echo "${C_BLD}Optional: lower post_max_size${C_OFF} (CVE-2026-109618, reduces memory pressure)"
  echo '  PHP suggests 8M if the sites take no file uploads, 32M if they do. Larger uploads or'
  echo '  very big forms will start to fail. Pool or per-site overrides still take precedence.'
  printf '  Choose: [1] 8M (no uploads)  [2] 32M (uploads)  [Enter] leave unchanged: '
  IFS= read -r answer
  case $answer in 1) post=8M up_fix=6M ;; 2) post=32M up_fix=30M ;; esac
  if [[ -n $post ]]; then
    content+="post_max_size = $post
"
    bytes=$(size_bytes "$post")
    for i in "${!CTX_INFO[@]}"; do
      (($(size_bytes "$(ini_val "${CTX_INFO[$i]}" upload_max_filesize)") >= bytes)) && need_upload=1
    done
    ((need_upload)) && content+="upload_max_filesize = $up_fix
"
  fi

  echo
  for d in "${dirs[@]}"; do write_dropin "$d" "$content"; done

  if ((mem)); then
    block="; >>> $MARK (remove with: php2shell-helper.sh --revert)
php_admin_value[memory_limit] = -1
; <<< $MARK"
    mapfile -t pools < <(fpm_pool_files)
    for f in "${pools[@]}"; do
      grep -q "$MARK" "$f" && continue
      if grep -qE '^[[:space:]]*php_(admin_)?value\[memory_limit\]' "$f"; then
        warn "  $f already sets memory_limit; change it to -1 there yourself (left untouched)."
        continue
      fi
      backup_file "$f"
      awk -v blk="$block" '{print} /^[[:space:]]*\[[^]]+\][[:space:]]*$/ && !/\[global\]/ {print blk}' "$f" >"$f.$MARK.tmp" &&
        cat "$f.$MARK.tmp" >"$f" && rm -f "$f.$MARK.tmp" && record "pool $f" && changed_pools+=("$f") &&
        good "  enforced php_admin_value[memory_limit] = -1 in $f"
    done
    if ((HAVE_MODPHP)) && conf=$(apache_conf_path) && [[ -n $conf ]]; then
      backup_file "$conf"
      cat >"$conf" <<EOF
# $MARK: temporary PHP2Shell mitigation for CVE-2026-109618. Not a fix: update PHP.
# Remove with: php2shell-helper.sh --revert
<IfModule php_module>
  php_admin_value memory_limit -1
</IfModule>
<IfModule php7_module>
  php_admin_value memory_limit -1
</IfModule>
EOF
      record "apache $conf"
      apache_conf=$conf
      [[ $conf == /etc/apache2/* ]] && have a2enconf && a2enconf -q php2shell-mitigation >/dev/null
      good "  enforced php_admin_value memory_limit -1 in $conf"
    fi
  fi

  echo
  echo 'Testing PHP-FPM / Apache configuration...'
  if ! validate_configs; then
    bad 'A configuration test failed. Undoing the server changes from this run; nothing was reloaded.'
    for f in "${changed_pools[@]}"; do cp -p -- "$BACKUP_DIR$f" "$f"; done
    if [[ -n $apache_conf ]]; then
      [[ $apache_conf == /etc/apache2/* ]] && have a2disconf && a2disconf -q php2shell-mitigation >/dev/null 2>&1
      rm -f -- "$apache_conf"
    fi
    validate_configs && good '  Configuration tests pass again.'
    return 1
  fi
  good '  Configuration tests passed.'
  [[ -n $BACKUP_DIR ]] && dim "  Backups of modified files: $BACKUP_DIR"
  offer_reload
  collect_contexts
  print_config
  cat <<'EOF'

Also worth doing (not automated, see README):
  * Remove per-request php_value / .htaccess / PHP_VALUE overrides you do not need.
  * Fix attacker-reachable fatal errors and timeouts (uploads, imports, callbacks).
  * At the proxy/WAF: cap request body size (including chunked requests), number of
    fields, multipart parts and headers per part; block multipart POSTs if unused.
  * pm.max_requests = 1 in FPM pools if performance allows (limits state reuse).
Now plan the real fix: option 3 in the menu.
EOF
}

revert() {
  local line kind f keep=0 content
  heading 'Remove temporary mitigations applied by php2shell-helper'
  if [[ ! -s $MANIFEST ]]; then echo 'Nothing to revert.'; return 0; fi
  echo 'PHP recommends keeping session.upload_progress.enabled=0 even after patching if you do not use it.'
  if confirm 'Keep session.upload_progress.enabled = 0 and remove everything else?'; then keep=1; fi
  while IFS= read -r line; do
    kind=${line%% *} f=${line#* }
    case $kind in
      dropin)
        [[ -f $f ]] || continue
        if ((keep)); then
          content="; $MARK: kept after revert on $(date -Is). Safe to delete if you need upload progress.
session.upload_progress.enabled = 0
"
          printf '%s' "$content" >"$f" && good "  reduced $f to session.upload_progress.enabled = 0"
        else
          rm -f -- "$f" && good "  removed $f"
        fi ;;
      pool)
        [[ -f $f ]] || continue
        sed -i "/^; >>> $MARK/,/^; <<< $MARK/d" "$f" && good "  removed memory_limit block from $f" ;;
      apache)
        [[ $f == /etc/apache2/* ]] && have a2disconf && a2disconf -q php2shell-mitigation >/dev/null 2>&1
        rm -f -- "$f" && good "  removed $f" ;;
    esac
  done <"$MANIFEST"
  if ((keep)); then grep '^dropin ' "$MANIFEST" >"$MANIFEST.tmp"; mv "$MANIFEST.tmp" "$MANIFEST"; else rm -f "$MANIFEST"; fi
  scan_host >/dev/null 2>&1
  validate_configs || warn 'A configuration test failed after revert; check the files above before reloading.'
  offer_reload
}

# ------------------------------------------------------------ containment ----
contain() {
  local -a units=() roles=() pick=()
  local u role line i answer engine id label failed=0 n
  heading 'Take vulnerable services offline'
  if has_systemd; then
    while IFS= read -r u; do
      case $u in
        apache2.service | httpd.service)
          if ((HAVE_MODPHP)); then role='Apache with mod_php: the PHP runtime itself (highest risk). Stops EVERY site on this Apache.'
          else role='Apache web server: stops EVERY site it serves, PHP or not.'; fi ;;
        nginx.service | caddy.service) role='web server/proxy in front of PHP: stops EVERY site it serves, PHP or not.' ;;
        lsws.service | lshttpd.service | openlitespeed.service) role='LiteSpeed web server and its lsphp workers: stops every site on it.' ;;
        frankenphp*) role='FrankenPHP app server: the PHP runtime itself.' ;;
        *) role='PHP-FPM runtime: PHP pages fail (502/503); static files keep being served.' ;;
      esac
      units+=("$u") roles+=("$role")
    done < <(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' |
      grep -E '^(apache2|httpd|nginx|caddy|frankenphp|lsws|lshttpd|openlitespeed|php[0-9.]*-fpm|php-fpm|php[0-9]+-php-fpm|ea-php[0-9]+-php-fpm|plesk-php[0-9]+-fpm|alt-php[0-9]+-fpm)(@[^ ]+)?\.service$')
  fi
  for line in "${CONTAINERS[@]}"; do
    read -r engine id label <<<"$line"
    units+=("$engine:$id") roles+=("container $label running unpatched or unverified PHP")
  done
  if ((${#units[@]} == 0)); then
    echo 'No running web/PHP systemd services or unpatched containers were found to stop.'
    echo 'If PHP runs another way (supervisor, a panel, a bare process), stop it with that tool,'
    echo 'or block access at the firewall / load balancer.'
    return 1
  fi
  cat <<EOF
${C_BLD}${C_RED}Read this first. Taking services offline:${C_OFF}
  * makes every site and API served by them unavailable IMMEDIATELY. Visitors get errors or
    "connection refused"; in-flight requests and uploads are cut off; webhooks, payment
    callbacks, cron jobs and integrations that call these sites fail; monitors will alert.
  * can shift traffic: a load balancer may send it to other nodes that may also be vulnerable.
  * fixes nothing. It only buys time. Enabled services start again on reboot, and panels,
    config management or auto-healing may restart them sooner.
  * does not undo a compromise that already happened. Check the exploitation signals above.
  Less disruptive alternatives: restrict access at the firewall/load balancer to trusted
  IPs, serve a static maintenance page, or block oversized/multipart POSTs at a WAF.

EOF
  for i in "${!units[@]}"; do printf '  [%d] %s\n      %s\n' $((i + 1)) "${units[$i]}" "${roles[$i]}"; done
  printf '\nEnter numbers to stop (e.g. "1 3"), "all", or press Enter to cancel: '
  IFS= read -r answer
  answer=${answer//,/ }
  if [[ $answer == all ]]; then
    pick=("${!units[@]}")
  else
    for n in $answer; do
      [[ $n =~ ^[0-9]+$ ]] && ((n >= 1 && n <= ${#units[@]})) && pick+=($((n - 1)))
    done
  fi
  if ((${#pick[@]} == 0)); then echo 'Cancelled. Nothing was stopped.'; return 1; fi
  echo 'You selected:'
  for i in "${pick[@]}"; do echo "  ${units[$i]}"; done
  printf 'Type %sSTOP%s to take them offline now, or anything else to cancel: ' "$C_BLD" "$C_OFF"
  IFS= read -r answer
  [[ $answer == STOP ]] || { echo 'Cancelled. Nothing was stopped.'; return 1; }
  local -a stopped_units=() stopped_ctrs=()
  for i in "${pick[@]}"; do
    u=${units[$i]}
    if [[ $u == *:* ]]; then
      engine=${u%%:*} id=${u#*:}
      if timeout 60 "$engine" stop "$id" >/dev/null; then good "  stopped container $id"; stopped_ctrs+=("$engine start $id")
      else bad "  FAILED to stop container $id"; failed=1; fi
    else
      if systemctl stop -- "$u" && [[ $(systemctl is-active -- "$u" 2>/dev/null) != active ]]; then
        good "  stopped $u"; stopped_units+=("$u")
      else bad "  FAILED to stop $u"; failed=1; fi
    fi
  done
  echo
  ((${#stopped_units[@]})) && {
    echo "Bring back after patching:   systemctl start ${stopped_units[*]}"
    echo "Keep down across reboots:    systemctl disable ${stopped_units[*]}   (re-enable later)"
  }
  for line in "${stopped_ctrs[@]}"; do echo "Bring container back:        $line   (better: redeploy from a fixed image)"; done
  ((${#stopped_ctrs[@]})) && dim 'Orchestrators (compose restart policies, Swarm, Kubernetes) may restart containers; scale them to zero there.'
  return $failed
}

# --------------------------------------------------------------- upgrade ----
upgrade_guidance() {
  local id='' like='' ver='' codename='' pretty='' pkgs=''
  heading 'How to upgrade safely on this host'
  if [[ -r /etc/os-release ]]; then
    # Read in a subshell so os-release variables cannot clobber this script's own.
    { IFS= read -r id; IFS= read -r like; IFS= read -r ver; IFS= read -r codename; IFS= read -r pretty; } < <(
      # shellcheck disable=SC1091
      . /etc/os-release
      printf '%s\n' "${ID:-}" "${ID_LIKE:-}" "${VERSION_ID:-}" "${VERSION_CODENAME:-}" "${PRETTY_NAME:-}"
    )
    echo "Detected: ${pretty:-$id $ver}"
  fi
  cat <<'EOF'

1. Prepare
   * Back up application files, databases and PHP / web-server configuration (or snapshot).
   * If you suspect compromise, preserve logs and a disk image before changing anything.
   * Patch staging first if you have it, but do not let that delay production for long.
EOF
  echo
  echo '2. Install fixed PHP packages'
  if [[ -d /usr/local/cpanel ]]; then
    cat <<'EOF'
   cPanel / EasyApache 4: ea-php82..ea-php85 moved to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12;
   cPanel reports backported fixes for ea-php74/80/81.
     dnf upgrade 'ea-php*'     (or: yum update 'ea-php*')
     /scripts/restartsrv_apache_php_fpm
EOF
  fi
  if [[ -e /etc/cloudlinux-release ]] || compgen -G '/opt/alt/php*' >/dev/null; then
    cat <<'EOF'
   CloudLinux alt-php: update every installed alt-php version (fixes are rolling out):
     yum update 'alt-php*'
   Note: "yum --security" may not list alt-php updates.
EOF
  fi
  if [[ -d /usr/local/psa ]]; then
    cat <<'EOF'
   Plesk: install the PHP handler updates (Tools & Settings > Updates, or
     plesk installer --select-release-current --upgrade-installed-components ).
   Plesk's 7.4/8.0/8.1 builds keep their version number; fixed builds are dated 21 Oct 2026.
EOF
  fi
  if [[ -d /usr/local/directadmin ]]; then
    echo '   DirectAdmin: update CustomBuild and rebuild every PHP version to a fixed release.'
  fi
  if have dpkg-query; then
    pkgs=$(dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null |
      awk '$1 == "ii" && $2 ~ /^(php[0-9]|libapache2-mod-php)/ {print $2}' | tr '\n' ' ')
    pkgs=${pkgs% }
    echo '   Debian / Ubuntu:'
    echo '     sudo apt-get update'
    echo "     apt list --upgradable 2>/dev/null | grep -E '^(php|libapache2-mod-php)'"
    [[ -n $pkgs ]] && echo "     sudo apt-get install --only-upgrade $pkgs"
    case "$id:$ver" in
      ubuntu:26.10) echo '     Fixed package (USN-8948-1): php8.5 8.5.9-0ubuntu2.1' ;;
      ubuntu:26.04) echo '     Fixed package (USN-8948-1): php8.5 8.5.4-0ubuntu1.5' ;;
      ubuntu:24.04) echo '     Fixed package (USN-8948-1): php8.3 8.3.6-0ubuntu0.24.04.13' ;;
      ubuntu:22.04) echo '     Fixed package (USN-8948-1): php8.1 8.1.2-1ubuntu2.28' ;;
      ubuntu:20.04 | ubuntu:18.04 | ubuntu:16.04 | ubuntu:14.04)
        echo '     This release is fixed only through Ubuntu Pro ESM (USN-8948-2): run "pro attach",'
        echo '     then upgrade. Without Pro, move to a supported release.' ;;
      debian:13) echo '     Fixed package (DSA-6574-1): php8.4 8.4.27-1~deb13u1' ;;
      debian:12) echo '     Fixed package (DLA-4848-1): php8.2 8.2.35-1~deb12u1' ;;
      debian:11 | debian:10 | debian:9) echo '     This release needs Debian ELTS or another LTS vendor; or move to a supported release.' ;;
    esac
    if grep -rqsE 'packages\.sury\.org|ondrej' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
      echo '     Sury / ondrej repository detected: it ships fixes for 5.6 through 8.5. Legacy'
      echo '     branches keep their old version numbers, so verify with the changelog (step 3).'
    fi
    if [[ $id == debian && -z $ver ]] || [[ $codename == forky ]]; then
      echo '     Debian testing (forky) was still listed as vulnerable on 22 Oct; check the security tracker.'
    fi
  fi
  if have rpm && [[ " $id $like " =~ \ (rhel|fedora|centos|almalinux|rocky|ol|amzn)\  ]]; then
    cat <<'EOF'
   RHEL family (RHEL, AlmaLinux, Rocky, Oracle, CentOS Stream, Fedora, Amazon Linux):
     sudo dnf check-update 'php*'
     sudo dnf upgrade 'php*'
     dnf module list php        (know which stream you are on; fixes are per stream)
   Fixed builds are backports: AlmaLinux uses ".alma.1" builds, Red Hat keeps version
   numbers. See Red Hat bulletin RHSB-2026-013 and your vendor's errata.
EOF
    if compgen -G '/etc/yum.repos.d/remi*.repo' >/dev/null; then
      warn '   Remi repository detected: PHP warned it would not have updates on 21 Oct. Confirm a'
      warn '   fixed build exists there, or switch to distribution packages or a source build.'
    fi
  fi
  if [[ " $id $like " =~ \ (suse|sles|opensuse)\  ]]; then
    echo "   SUSE: sudo zypper refresh && sudo zypper update 'php8*'"
  fi
  if [[ $id == alpine ]]; then
    echo "   Alpine: sudo apk update && sudo apk upgrade   (fixed php8x packages are in newer"
    echo '   Alpine branches; check the Alpine security tracker for your release).'
  fi
  cat <<'EOF'
   Containers: host updates do NOT fix images. Rebuild from a fixed base image
     (php:8.5.12+, 8.4.27+, 8.3.36+ or 8.2.35+; FrankenPHP releases bundling these) with
     docker build --pull --no-cache ... and redeploy. Do not just restart the old image.
   Built from source: build 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or for 7.4 / 8.0 / 8.1 use
     PHP's minimal source backports (branches PHP-<ver>-CVE-2026-109618-109619 on php-src).
   PHP 8.1 and older: plan a move to a supported branch even after applying a backport.
   PHP 8.2 reaches end of life on 31 Dec 2026.
EOF
  cat <<'EOF'

3. Verify the package, not just "php -v" (vendor backports often keep the version):
EOF
  if have dpkg-query; then
    echo "     zgrep -cE 'CVE-2026-10961[89]' /usr/share/doc/php*-common/changelog.Debian.gz"
  fi
  have rpm && echo "     rpm -qa 'php*' | xargs -n1 rpm -q --changelog | grep -E 'CVE-2026-10961[89]'"
  echo '   Both CVE IDs should appear.'
  cat <<'EOF'

4. Restart EVERY PHP worker. Running workers keep the old code in memory until restarted.
     systemctl restart php*-fpm apache2       (httpd on RHEL family)
     pkill lsphp                               (LiteSpeed: restarting lsws is not enough)
   Use a full restart, not a reload: with mod_php, a graceful reload (apachectl graceful,
   apachectl restart, systemctl reload) can keep the OLD module loaded in Apache's parent
   process. This tool reports that case as RESTART-NEEDED.
   Also restart queue workers, schedulers, supervisord programs and any long-running
   "php" daemons, and redeploy containers.

5. Re-run this tool. Every runtime should read PATCHED or PATCHED-VENDOR, with no
   RESTART-NEEDED. Then run application smoke tests and restore normal access.

6. Afterwards: you may remove temporary mitigations (--revert); keeping
   session.upload_progress.enabled=0 is recommended if you do not use it. If the host was
   exposed while vulnerable, review the exploitation signals and rotate secrets the web
   user could read (database passwords, API keys) if anything looks suspicious.
EOF
}

# ------------------------------------------------------------------ main ----
if [[ $MODE == revert ]]; then
  revert
  exit $?
fi

detect
if ((${#R_STATUS[@]} == 0)); then exit 3; fi
if [[ $MODE == report ]]; then exit $((ACTION_NEEDED > 0)); fi
if [[ ! -t 0 ]]; then
  dim 'Noninteractive run: no changes made. Use a terminal for the response menu.'
  exit $((ACTION_NEEDED > 0))
fi
if ((ACTION_NEEDED == 0)); then exit 0; fi

while :; do
  cat <<EOF

${C_BLD}What would you like to do?${C_OFF}  (nothing changes without a further confirmation)
  [1] Apply temporary mitigations  (reduce exposure while you patch)
  [2] Take vulnerable services offline  (stop the risk; sites go down)
  [3] Show how to upgrade safely on this host  (the real fix)
  [4] What is PHP2Shell and why act now?
  [5] Re-run detection
  [q] Quit
EOF
  printf 'Choice: '
  IFS= read -r choice || break
  case $choice in
    1) mitigate ;;
    2) contain ;;
    3) upgrade_guidance ;;
    4) explain ;;
    5) detect ;;
    q | Q | '') break ;;
    *) echo 'Please choose 1-5 or q.' ;;
  esac
done
exit $((ACTION_NEEDED > 0))
