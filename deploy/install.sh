#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source "$repo_dir/deploy/install-ack.sh"
source "$repo_dir/deploy/install-workspace.sh"
[[ $# -eq 0 ]] || ff_die 'This installer accepts no acknowledgment bypass flags.'
[[ "$(id -u)" == 0 ]] || ff_die 'Run this installer as root.'
[[ "$(uname -s)" == Linux ]] || ff_die 'Installation requires Linux and systemd.'
[[ -d /run/systemd/system ]] || ff_die 'Installation requires a running systemd system manager.'
for dependency in stat install mktemp systemctl awk tar sha256sum df; do
  command -v "$dependency" >/dev/null || ff_die "Required command is missing: $dependency"
done
ff_require_ack
ff_prepare_workspace
source "$repo_dir/deploy/install-runtime.sh"
ff_install "$repo_dir" "$work_dir"
