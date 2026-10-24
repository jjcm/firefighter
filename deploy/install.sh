#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source "$repo_dir/deploy/install-ack.sh"
[[ $# -eq 0 ]] || ff_die 'This installer accepts no acknowledgment bypass flags.'
[[ "$(id -u)" == 0 ]] || ff_die 'Run this installer as root on the Ubuntu server.'
[[ "$(uname -s)" == Linux ]] || ff_die 'Installation requires Ubuntu Linux.'
[[ -r /etc/os-release ]] || ff_die 'Cannot identify this Linux distribution.'
os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
[[ "$os_id" == ubuntu ]] || ff_die 'This installer supports Ubuntu only.'
for binary in firefighter firefighter-grokbot; do
  [[ -x "$repo_dir/bin/$binary" ]] || ff_die 'Build first with make build on Ubuntu (or copy the correct Linux binaries into bin/).'
done
ff_require_ack
for target in /etc/firefighter /var/lib/firefighter /usr/local/bin /etc/firefighter-grokbot \
  /usr/local/bin/firefighter /usr/local/bin/firefighter-grokbot \
  /etc/firefighter/config.json /etc/firefighter/firefighter.env /etc/firefighter/grokbot.env \
  /etc/firefighter-grokbot/config.json /etc/systemd/system/firefighter.service /etc/systemd/system/firefighter-grokbot.service; do
  [[ ! -L "$target" ]] || ff_die "Refusing symlink installation target: $target"
done
for target in /etc/firefighter/config.json /etc/firefighter/firefighter.env /etc/firefighter/grokbot.env /etc/firefighter-grokbot/config.json; do
  [[ ! -e "$target" || -f "$target" ]] || ff_die "Expected a regular file: $target"
done
install -d -o 0 -g 0 -m 0700 /etc/firefighter /var/lib/firefighter
install -d -o 0 -g 0 -m 0755 /usr/local/bin
binary_temp=''
trap '[[ -z "$binary_temp" ]] || rm -f -- "$binary_temp"' EXIT
for binary in firefighter firefighter-grokbot; do
  binary_temp=$(mktemp "/usr/local/bin/.$binary.XXXXXX")
  install -o 0 -g 0 -m 0755 "$repo_dir/bin/$binary" "$binary_temp"
  mv -T -- "$binary_temp" "/usr/local/bin/$binary"
  binary_temp=''
done
if [[ ! -e /etc/firefighter/config.json ]]; then
  install -o 0 -g 0 -m 0600 "$repo_dir/deploy/firefighter-config.json" /etc/firefighter/config.json
fi
if [[ ! -e /etc/firefighter/firefighter.env ]]; then
  install -o 0 -g 0 -m 0600 "$repo_dir/deploy/firefighter-bootstrap.env.example" /etc/firefighter/firefighter.env
fi
if [[ ! -e /etc/firefighter/grokbot.env ]]; then
  install -o 0 -g 0 -m 0600 "$repo_dir/deploy/grokbot.env.example" /etc/firefighter/grokbot.env
fi
install -d -o 0 -g 0 -m 0755 /etc/firefighter-grokbot
if [[ ! -e /etc/firefighter-grokbot/config.json ]]; then
  install -o 0 -g 0 -m 0644 "$repo_dir/plugins/grokbot/config.example.json" /etc/firefighter-grokbot/config.json
fi
chown 0:0 /etc/firefighter/config.json /etc/firefighter/firefighter.env /etc/firefighter/grokbot.env
chmod 0600 /etc/firefighter/config.json /etc/firefighter/firefighter.env /etc/firefighter/grokbot.env
install -o 0 -g 0 -m 0644 "$repo_dir/deploy/firefighter.service" /etc/systemd/system/firefighter.service
install -o 0 -g 0 -m 0644 "$repo_dir/plugins/grokbot/firefighter-grokbot.service" /etc/systemd/system/firefighter-grokbot.service
systemctl daemon-reload
ff_record_ack
printf '%s\n' \
  'Installed. Set OPENROUTER_API_KEY in /etc/firefighter/firefighter.env and review /etc/firefighter/config.json.' \
  'Existing configuration and secrets were preserved. The shared feed needs no client X/Twitter credential.' \
  'Grokbot configuration: /etc/firefighter-grokbot/config.json' \
  'Start autonomous defense when configured: systemctl enable --now firefighter' \
  'Start configured reporting plugin: systemctl enable --now firefighter-grokbot' \
  'This installer did not start or restart either daemon.'
