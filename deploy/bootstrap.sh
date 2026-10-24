#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

# Fixed reviewed source revision; update only after publishing the source commit.
FF_SOURCE_REV=dfd2cd978f2e26f3ddedc6b155e7e0335436c486
FF_SOURCE_REPOSITORY=https://github.com/jjcm/firefighter.git

# Self-contained copy of install-ack.sh; deploy/test_install.py checks equality.
# BEGIN FIREFIGHTER INSTALL ACK
FF_ACK_PHRASE='I understand the risks and that this might delete my entire server.'
FF_ACK_PATH=/etc/firefighter/install-risk-acknowledgment

ff_die() { printf '%s\n' "$*" >&2; exit 1; }

ff_require_ack() {
  if [[ -e /etc/firefighter || -L /etc/firefighter ]]; then
    [[ -d /etc/firefighter && ! -L /etc/firefighter ]] || ff_die 'Expected a real directory at /etc/firefighter, not a symlink.'
    local directory_metadata directory_mode
    directory_metadata=$(stat -c '%u:%a' -- /etc/firefighter)
    [[ "$directory_metadata" == 0:* ]] || ff_die '/etc/firefighter must be owned by root.'
    directory_mode=${directory_metadata#*:}
    [[ "$directory_mode" =~ ^[0-7]{3,4}$ ]] || ff_die 'Cannot verify /etc/firefighter permissions.'
    (( (8#$directory_mode & 0022) == 0 )) || ff_die '/etc/firefighter must not be writable by group or other users.'
  fi
  if [[ -e "$FF_ACK_PATH" || -L "$FF_ACK_PATH" ]]; then
    [[ ! -L "$FF_ACK_PATH" && -f "$FF_ACK_PATH" ]] || ff_die 'The install acknowledgment must be a regular file, not a symlink.'
    [[ "$(stat -c '%u:%a' -- "$FF_ACK_PATH")" == '0:600' ]] || ff_die 'The install acknowledgment must be owned by root with mode 0600.'
    local recorded
    IFS= read -r recorded < "$FF_ACK_PATH" || ff_die 'The install acknowledgment is invalid.'
    [[ "$recorded" == "$FF_ACK_PHRASE" ]] || ff_die 'The install acknowledgment is invalid.'
    return
  fi
  # Read the controlling terminal, never the script/pipe on standard input.
  if ! { exec 3<>/dev/tty; } 2>/dev/null; then
    ff_die 'First installation needs an interactive terminal to acknowledge the risks. Run this command from a terminal; no unattended override is provided.'
  fi
  [[ -t 3 ]] || ff_die 'First installation needs an interactive terminal.'
  printf '\nFirefighter runs an autonomous agent as root and can change or delete this server.\nTo install, type this exact sentence:\n%s\n> ' "$FF_ACK_PHRASE" >&3
  local answer
  if ! IFS= read -r answer <&3; then
    exec 3>&-
    ff_die 'Installation canceled: no acknowledgment received.'
  fi
  exec 3>&-
  [[ "$answer" == "$FF_ACK_PHRASE" ]] || ff_die 'Installation canceled: the acknowledgment did not match exactly.'
}

ff_record_ack() {
  # Call only after installation and automatic service startup succeed.
  [[ ! -e "$FF_ACK_PATH" ]] || return 0
  local marker
  marker=$(mktemp /etc/firefighter/.install-risk-acknowledgment.XXXXXX)
  printf '%s\n' "$FF_ACK_PHRASE" > "$marker"
  chmod 0600 "$marker"
  chown 0:0 "$marker"
  mv -T -- "$marker" "$FF_ACK_PATH"
}
# END FIREFIGHTER INSTALL ACK

# Self-contained copy of install-workspace.sh; fixtures check equality.
# BEGIN FIREFIGHTER INSTALL WORKSPACE
ff_prepare_workspace() {
  local available_kib minimum_kib=2097152
  [[ -d /var/tmp && ! -L /var/tmp ]] || ff_die 'Build workspace requires a real directory at /var/tmp.'
  available_kib=$(df -Pk /var/tmp | awk 'NR == 2 { print $4 }') || ff_die 'Cannot check available build space in /var/tmp.'
  [[ "$available_kib" =~ ^[0-9]+$ ]] || ff_die 'Cannot determine available build space in /var/tmp.'
  available_kib=$((10#$available_kib))
  if (( available_kib < minimum_kib )); then
    ff_die "Not enough disk space in /var/tmp: $((available_kib / 1024)) MiB available; at least 2048 MiB (2 GiB) is required to compile Firefighter. Free space on that filesystem and retry."
  fi
  # /tmp is often a small RAM-backed filesystem on VPS images. Keep the source,
  # compiler, caches, and Go's temporary build outputs together on /var/tmp.
  work_dir=$(mktemp -d /var/tmp/firefighter-install.XXXXXX)
  FF_INSTALL_TEMP=''
  trap 'rm -rf -- "$work_dir"; [[ -z "$FF_INSTALL_TEMP" ]] || rm -f -- "$FF_INSTALL_TEMP"' EXIT
  install -d -o 0 -g 0 -m 0700 "$work_dir/tmp"
  export TMPDIR="$work_dir/tmp" GOTMPDIR="$work_dir/tmp"
}
# END FIREFIGHTER INSTALL WORKSPACE

main() {
  [[ $# -eq 0 ]] || ff_die 'This installer accepts no arguments or acknowledgment bypass flags.'
  [[ "$(id -u)" == 0 ]] || ff_die 'Run as root: curl -fsSL https://45.76.243.18/install.sh | sudo bash'
  [[ "$(uname -s)" == Linux ]] || ff_die 'Installation requires Linux and systemd.'
  [[ -d /run/systemd/system ]] || ff_die 'Installation requires a running systemd system manager.'
  for dependency in stat install mktemp systemctl awk tar sha256sum df; do
    command -v "$dependency" >/dev/null || ff_die "Required command is missing: $dependency"
  done
  [[ "$FF_SOURCE_REV" =~ ^[0-9a-f]{40}$ ]] || ff_die 'The installer has an invalid source revision.'
  ff_require_ack
  ff_prepare_workspace
  if ! command -v git >/dev/null; then
    printf 'Installing git to retrieve the reviewed source.\n'
    if command -v apt-get >/dev/null; then
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git ca-certificates
    elif command -v dnf >/dev/null; then
      dnf install -y git ca-certificates
    elif command -v yum >/dev/null; then
      yum install -y git ca-certificates
    elif command -v pacman >/dev/null; then
      pacman -S --needed --noconfirm git ca-certificates
    elif command -v zypper >/dev/null; then
      zypper --non-interactive install git ca-certificates
    else
      ff_die "Install git with your system's package manager, then retry."
    fi
  fi
  command -v git >/dev/null || ff_die 'Git installation failed.'
  source_dir="$work_dir/source"
  # No moving branch or remote installer script is executed. Git verifies object
  # hashes; checkout must resolve to the exact revision embedded above.
  export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
  git -c init.defaultBranch=main init --quiet "$source_dir"
  git -C "$source_dir" remote add origin "$FF_SOURCE_REPOSITORY"
  git -C "$source_dir" -c http.sslVerify=true -c protocol.file.allow=never fetch --quiet --depth=1 origin "$FF_SOURCE_REV"
  git -C "$source_dir" -c core.hooksPath=/dev/null checkout --quiet --detach FETCH_HEAD
  [[ "$(git -C "$source_dir" rev-parse --verify HEAD)" == "$FF_SOURCE_REV" ]] || ff_die 'Fetched source does not match the pinned revision.'
  source "$source_dir/deploy/install-runtime.sh"
  ff_install "$source_dir" "$work_dir"
}

# No installer work happens until this entire function has been received.
main "$@"
