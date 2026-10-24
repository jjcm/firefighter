#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root on the Ubuntu server." >&2
  exit 1
fi
if [ "$(uname -s)" != Linux ]; then
  echo "Installation requires Linux." >&2
  exit 1
fi
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
for binary in firefighter firefighter-grokbot; do
  if [ ! -x "$repo_dir/bin/$binary" ]; then
    echo "Build first with make build on the Ubuntu server (or copy the correct Linux binaries into bin/)." >&2
    exit 1
  fi
done
install -d -m 0700 /etc/firefighter /var/lib/firefighter
install -m 0755 "$repo_dir/bin/firefighter" /usr/local/bin/firefighter
install -m 0755 "$repo_dir/bin/firefighter-grokbot" /usr/local/bin/firefighter-grokbot
if [ ! -e /etc/firefighter/config.json ]; then
  /usr/local/bin/firefighter init --config /etc/firefighter/config.json
fi
if [ ! -e /etc/firefighter/firefighter.env ]; then
  install -m 0600 "$repo_dir/deploy/firefighter.env.example" /etc/firefighter/firefighter.env
fi
if [ ! -e /etc/firefighter/grokbot.env ]; then
  install -m 0600 "$repo_dir/deploy/grokbot.env.example" /etc/firefighter/grokbot.env
fi
# DynamicUser needs traversal/read access to its non-secret configuration only.
install -d -m 0755 /etc/firefighter-grokbot
if [ ! -e /etc/firefighter-grokbot/config.json ]; then
  install -m 0644 "$repo_dir/plugins/grokbot/config.example.json" /etc/firefighter-grokbot/config.json
fi
install -m 0644 "$repo_dir/deploy/firefighter.service" /etc/systemd/system/firefighter.service
install -m 0644 "$repo_dir/plugins/grokbot/firefighter-grokbot.service" /etc/systemd/system/firefighter-grokbot.service
systemctl daemon-reload
echo "Installed. Configure /etc/firefighter/config.json and the root-only environment files."
echo "Grokbot configuration: /etc/firefighter-grokbot/config.json"
echo "Start autonomous defense: systemctl enable --now firefighter"
echo "Start configured reporting plugin: systemctl enable --now firefighter-grokbot"
