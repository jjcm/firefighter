#!/usr/bin/env bash
# Shared build workspace setup. bootstrap.sh embeds this exact block.
# Entry points must call ff_require_ack before ff_prepare_workspace.
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
