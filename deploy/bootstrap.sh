#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

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
  # Call only after all installation steps and daemon-reload succeed.
  [[ ! -e "$FF_ACK_PATH" ]] || return 0
  local marker
  marker=$(mktemp /etc/firefighter/.install-risk-acknowledgment.XXXXXX)
  printf '%s\n' "$FF_ACK_PHRASE" > "$marker"
  chmod 0600 "$marker"
  chown 0:0 "$marker"
  mv -T -- "$marker" "$FF_ACK_PATH"
}
# END FIREFIGHTER INSTALL ACK

main() {
  [[ $# -eq 0 ]] || ff_die 'This installer accepts no arguments or acknowledgment bypass flags.'
  [[ "$(id -u)" == 0 ]] || ff_die 'Run as root: curl -fsSL https://45.76.243.18/install.sh | sudo bash'
  [[ "$(uname -s)" == Linux ]] || ff_die 'This installer requires Ubuntu Linux.'
  [[ -r /etc/os-release ]] || ff_die 'Cannot identify this Linux distribution.'
  os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
  [[ "$os_id" == ubuntu ]] || ff_die 'This installer supports Ubuntu only.'
  case "$(uname -m)" in
    x86_64|amd64) architecture=amd64 ;;
    aarch64|arm64) architecture=arm64 ;;
    *) ff_die 'Supported architectures are amd64 and arm64.' ;;
  esac
  for dependency in curl sha256sum stat install mktemp systemctl awk grep; do
    command -v "$dependency" >/dev/null || ff_die "Required command is missing: $dependency"
  done
  ff_require_ack

  base_url=https://45.76.243.18
  hub_public_key='Ew1Q+MQs4h4gb1JiiUdY/IQ3i4iLdYtslH5DrsWTduI='
  work_dir=$(mktemp -d /tmp/firefighter-install.XXXXXX)
  binary_temp=''
  trap 'rm -rf -- "$work_dir"; [[ -z "$binary_temp" ]] || rm -f -- "$binary_temp"' EXIT
  download() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --tlsv1.2 --connect-timeout 15 --max-time 180 --max-filesize 104857600 \
      --retry 2 --output "$work_dir/$1" "$base_url/downloads/$1"
  }
  download SHA256SUMS
  artifacts=("firefighter-linux-$architecture" firefighter-config.json firefighter.env.example firefighter.service)
  for artifact in "${artifacts[@]}"; do
    download "$artifact"
    # Select one named entry; never execute a manifest's arbitrary paths.
    expected=$(awk -v name="$artifact" '$2 == name { print $1 }' "$work_dir/SHA256SUMS")
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || ff_die "Missing, duplicate, or invalid checksum for $artifact. Nothing was installed."
    actual=$(sha256sum "$work_dir/$artifact")
    actual=${actual%% *}
    [[ "$actual" == "$expected" ]] || ff_die "Checksum verification failed for $artifact. Nothing was installed."
  done
  # Key changes require updating the bootstrap and template together. Existing
  # local configuration remains untouched on upgrades.
  grep -Fq '"url": "https://45.76.243.18"' "$work_dir/firefighter-config.json" || ff_die 'The default feed endpoint does not match this installer.'
  grep -Fq "\"public_key\": \"$hub_public_key\"" "$work_dir/firefighter-config.json" || ff_die 'The default feed signing key does not match this installer.'

  for target in /etc/firefighter /var/lib/firefighter /usr/local/bin /usr/local/bin/firefighter \
    /etc/firefighter/config.json /etc/firefighter/firefighter.env /etc/systemd/system/firefighter.service; do
    [[ ! -L "$target" ]] || ff_die "Refusing symlink installation target: $target"
  done
  for target in /etc/firefighter/config.json /etc/firefighter/firefighter.env; do
    [[ ! -e "$target" || -f "$target" ]] || ff_die "Expected a regular file: $target"
  done
  install -d -o 0 -g 0 -m 0700 /etc/firefighter /var/lib/firefighter
  install -d -o 0 -g 0 -m 0755 /usr/local/bin
  binary_temp=$(mktemp /usr/local/bin/.firefighter.XXXXXX)
  install -o 0 -g 0 -m 0755 "$work_dir/firefighter-linux-$architecture" "$binary_temp"
  mv -T -- "$binary_temp" /usr/local/bin/firefighter
  binary_temp=''
  if [[ ! -e /etc/firefighter/config.json ]]; then
    install -o 0 -g 0 -m 0600 "$work_dir/firefighter-config.json" /etc/firefighter/config.json
  fi
  if [[ ! -e /etc/firefighter/firefighter.env ]]; then
    install -o 0 -g 0 -m 0600 "$work_dir/firefighter.env.example" /etc/firefighter/firefighter.env
  fi
  chown 0:0 /etc/firefighter/config.json /etc/firefighter/firefighter.env
  chmod 0600 /etc/firefighter/config.json /etc/firefighter/firefighter.env
  install -o 0 -g 0 -m 0644 "$work_dir/firefighter.service" /etc/systemd/system/firefighter.service
  systemctl daemon-reload
  ff_record_ack
  printf '\nInstalled Firefighter for Ubuntu %s. Existing configuration and credentials were preserved.\n' "$architecture"
  printf '%s\n' \
    'Set OPENROUTER_API_KEY in /etc/firefighter/firefighter.env and review /etc/firefighter/config.json.' \
    'To use another LLM provider, change llm.base_url, llm.model, and llm.api_key_env in that config.' \
    'The shared signed intelligence feed requires no client X/Twitter credential.' \
    'When configured, start once: sudo systemctl enable --now firefighter' \
    'This installer did not start or restart the daemon. Restart a configured running upgrade at a safe point.' \
    'Local audit: /var/lib/firefighter/audit.jsonl. Optional Grokbot reporting is configured separately.'
}

# No installer work happens until the entire function has been received.
main "$@"
