#!/usr/bin/env bash
# Shared first-install acknowledgment. bootstrap.sh embeds this exact block.
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
