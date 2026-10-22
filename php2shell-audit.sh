#!/usr/bin/env bash
# PHP2Shell defensive inventory — CVE-2026-109618 / CVE-2026-109619
set -uo pipefail
export LC_ALL=C
shopt -s nullglob

if (( EUID != 0 )); then echo 'Run with sudo: sudo bash php2shell-audit.sh' >&2; exit 2; fi
declare -A visited=() seen_modules=()
declare -a stop_units=()
risk=0
incomplete=0
checked=0

version_status() {
  local v=$1 major minor patch limit
  if [[ ! $v =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then echo UNKNOWN; return; fi
  major=$((10#${BASH_REMATCH[1]}))
  minor=$((10#${BASH_REMATCH[2]}))
  patch=$((10#${BASH_REMATCH[3]}))
  if (( major < 8 || (major == 8 && minor < 2) )); then echo EOL-REVIEW; return; fi
  case "$major.$minor" in
    8.2) limit=35;; 8.3) limit=36;; 8.4) limit=27;; 8.5) limit=12;;
    *) echo UNKNOWN-BRANCH; return;;
  esac
  if (( patch < limit )); then echo BELOW-UPSTREAM-FIX; else echo UPSTREAM-FIXED; fi
}
check_binary() {
  local file=$1 source=$2 key output version status
  [[ -f $file && -x $file ]] || return 0
  key=$(readlink -f -- "$file" 2>/dev/null || printf '%s' "$file")
  [[ ! ${visited[$key]+present} ]] || return 0
  visited[$key]=1
  output=$(timeout 5 "$file" -v 2>/dev/null | head -n 1 || :)
  version=$(sed -nE 's/.*PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' <<< "$output")
  status=$(version_status "$version")
  printf '%-18s %-12s %-22s %s\n' "$source" "${version:-?}" "$status" "$key"
  ((checked+=1))
  [[ $status == UPSTREAM-FIXED ]] || risk=1
}
printf 'PHP2Shell audit | %s | %s\n' "$(date -Is)" "$(hostname)"
echo '== PHP host executables, installed trees and live processes =='
for exe in php php-cgi php-fpm lsphp frankenphp; do
  path=$(command -v "$exe" 2>/dev/null || :)
  [[ -z $path ]] || check_binary "$path" PATH
done
for path in /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm* /opt/php*/bin/php /opt/php*/sbin/php-fpm /opt/alt/php*/usr/bin/php /opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm /usr/local/lsws/lsphp*/bin/lsphp; do
  [[ -f $path && -x $path ]] && check_binary "$path" disk
done
for proc in /proc/[0-9]*; do
  [[ -r $proc/comm ]] || continue
  IFS= read -r name < "$proc/comm" || continue
  case $name in php*|lsphp*|frankenphp*|apache2|httpd) ;; *) continue;; esac
  target=$(readlink "$proc/exe" 2>/dev/null || :)
  if [[ $name == apache2 || $name == httpd ]]; then
    if [[ -r $proc/maps ]]; then
      while IFS= read -r lib; do
        [[ -n $lib && ! ${seen_modules[$lib]+present} ]] || continue
        seen_modules[$lib]=1
        echo "Apache PHP module: $lib"
        # A module loaded by Apache is not necessarily the CLI PHP version.
        risk=1
      done < <(grep -oE '/[^ ]*/(libphp[^ /]*\.so|php[^ /]*\.so)' "$proc/maps" 2>/dev/null | sort -u)
    else
      echo "Cannot inspect Apache process PID ${proc##*/}"
      incomplete=1
    fi
  elif [[ -n $target && $target != *' (deleted)'* ]]; then
    check_binary "$proc/exe" "pid:${proc##*/}"
  else
    echo "Unverifiable active PHP process PID ${proc##*/}: $name"
    incomplete=1
  fi
done

echo
echo '== Installed PHP packages (consult vendor security advisories for backports) =='
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${binary:Package} ${Version}\n' 'php*' 'libapache2-mod-php*' 2>/dev/null | head -n 80 || :
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' | grep -Ei '(^php|^ea-php|^lsphp)' | head -n 80 || :
fi

echo
echo '== Running Docker / Podman containers =='
for engine in docker podman; do
  command -v "$engine" >/dev/null 2>&1 || continue
  if ! ids=$("$engine" ps -q 2>/dev/null); then
    echo "$engine inventory failed"; incomplete=1; continue
  fi
  for id in $ids; do
    label=$("$engine" inspect --format '{{.Name}} {{.Config.Image}}' "$id" 2>/dev/null || printf '%s' "$id")
    output=$("$engine" exec "$id" sh -c 'for x in php php-fpm php-cgi lsphp frankenphp; do command -v "$x" >/dev/null 2>&1 && "$x" -v 2>/dev/null | head -1; done' 2>/dev/null || :)
    if [[ $output == *PHP* ]]; then
      while IFS= read -r line; do
        [[ $line == *PHP* ]] || continue
        version=$(sed -nE 's/.*PHP ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' <<< "$line")
        status=$(version_status "$version")
        printf '%-18s %-12s %-22s %s\n' "$engine:$id" "${version:-?}" "$status" "$label"
        ((checked+=1))
        [[ $status == UPSTREAM-FIXED ]] || risk=1
      done <<< "$output"
    else
      echo "Container requires inspection: $label"
      incomplete=1
    fi
  done
done

echo
echo '== Active web-serving systemd services =='
if command -v systemctl >/dev/null 2>&1; then
  mapfile -t stop_units < <(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}' | grep -E '^(apache2|httpd|nginx|php([0-9]+\.[0-9]+)?-fpm|php-fpm|lsws|openlitespeed|caddy)(@[^ ]+)?\.service$' | sort -u || :)
  printf '%s\n' "${stop_units[@]}"
fi
echo
echo '== Assessment =='
((checked > 0)) || incomplete=1
if (( risk || incomplete )); then
  ((risk)) && echo 'REVIEW REQUIRED: A runtime is below the upstream fixed version or not verified.'
  ((incomplete)) && echo 'INCOMPLETE: At least one PHP installation or container could not be checked.'
  echo 'Install fixes for both CVEs or verify vendor security backports.'
else
  echo 'Discovered version-reporting runtimes meet upstream fixed release thresholds.'
  echo 'Confirm package authenticity and any vendor security backport status.'
  exit 0
fi
echo 'PHP advisory: https://www.php.net/archive/2026.php#2026-10-21-5'
if (( ${#stop_units[@]} == 0 )); then exit 1; fi
if [[ ! -t 0 ]]; then echo 'Noninteractive: no changes made.'; exit 1; fi
echo 'Stopping ALL listed web-serving systemd services interrupts websites. It does not stop containers.'
printf 'Type STOP to stop these services immediately, or anything else to cancel: '
IFS= read -r answer
[[ $answer == STOP ]] || { echo 'Cancelled.'; exit 1; }
failed=0
for unit in "${stop_units[@]}"; do
  if systemctl stop -- "$unit"; then echo "Stopped: $unit"; else echo "FAILED: $unit"; failed=1; fi
done
for unit in "${stop_units[@]}"; do
  if [[ $(systemctl is-active "$unit" 2>/dev/null || :) == active ]]; then
    echo "Still running: $unit"; failed=1
  fi
done
echo 'Verify isolation, back up, install patched PHP packages/images, restart workers and test before restoring service.'
exit "$failed"
