#!/usr/bin/env bash
# Shared implementation. Entry points must call ff_require_ack before sourcing.
# This file is intentionally not an executable installation entry point.

ff_dependencies() {
  local missing=() dependency
  for dependency in "$@"; do
    command -v "$dependency" >/dev/null || missing+=("$dependency")
  done
  [[ ${#missing[@]} -gt 0 ]] || return 0
  printf 'Installing missing build tools: %s\n' "${missing[*]}"
  if command -v apt-get >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}" ca-certificates
  elif command -v dnf >/dev/null; then
    dnf install -y "${missing[@]}" ca-certificates
  elif command -v yum >/dev/null; then
    yum install -y "${missing[@]}" ca-certificates
  elif command -v pacman >/dev/null; then
    # Arch names its Python 3 package python.
    local packages=() package
    for package in "${missing[@]}"; do
      [[ "$package" != python3 ]] || package=python
      packages+=("$package")
    done
    pacman -S --needed --noconfirm "${packages[@]}" ca-certificates
  elif command -v zypper >/dev/null; then
    zypper --non-interactive install "${missing[@]}" ca-certificates
  else
    ff_die "Install these tools with your system's package manager, then retry: ${missing[*]}"
  fi
  for dependency in "$@"; do
    command -v "$dependency" >/dev/null || ff_die "Required command is still missing: $dependency"
  done
}

ff_download() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --connect-timeout 15 --max-time 600 --max-filesize 268435456 \
    --retry 2 --output "$2" "$1"
}

ff_select_go() {
  local source_dir=$1 work_dir=$2 minimum installed='' architecture metadata
  minimum=$(awk '$1 == "go" { print $2; exit }' "$source_dir/go.mod")
  [[ "$minimum" =~ ^1\.[0-9]+(\.[0-9]+)?$ ]] || ff_die 'Cannot determine the required Go version.'
  if command -v go >/dev/null; then
    installed=$(GOTOOLCHAIN=local GOENV=off go env GOVERSION 2>/dev/null || true)
    if python3 "$source_dir/deploy/install-config.py" go-version "$installed" "$minimum"; then
      FF_GO=$(command -v go)
      return
    fi
  fi
  case "$(uname -m)" in
    x86_64|amd64) architecture=amd64 ;;
    aarch64|arm64) architecture=arm64 ;;
    i386|i486|i586|i686) architecture=386 ;;
    armv6l|armv7l|armv8l) architecture=armv6l ;;
    ppc64le|s390x|riscv64|loong64) architecture=$(uname -m) ;;
    *) ff_die 'No bundled toolchain is available for this architecture. Install a compatible Go toolchain and run this installer again.' ;;
  esac
  printf 'Fetching a verified Go toolchain for local compilation (%s).\n' "$architecture"
  ff_download 'https://go.dev/dl/?mode=json' "$work_dir/go-releases.json"
  metadata=$(python3 "$source_dir/deploy/install-config.py" go-release "$work_dir/go-releases.json" "$architecture" "$minimum")
  local filename expected actual
  IFS=' ' read -r filename expected <<< "$metadata"
  [[ "$filename" =~ ^go1\.[0-9]+(\.[0-9]+)?\.linux-[a-z0-9]+\.tar\.gz$ && "$expected" =~ ^[0-9a-f]{64}$ ]] || ff_die 'Invalid Go release metadata.'
  ff_download "https://go.dev/dl/$filename" "$work_dir/go.tar.gz"
  actual=$(sha256sum "$work_dir/go.tar.gz"); actual=${actual%% *}
  [[ "$actual" == "$expected" ]] || ff_die 'Go toolchain checksum verification failed.'
  tar -xzf "$work_dir/go.tar.gz" -C "$work_dir"
  FF_GO="$work_dir/go/bin/go"
  [[ -x "$FF_GO" ]] || ff_die 'The Go toolchain did not contain an executable compiler.'
}

ff_atomic_install() {
  local source=$1 destination=$2 mode=$3
  FF_INSTALL_TEMP=$(mktemp "${destination%/*}/.firefighter-install.XXXXXX")
  install -o 0 -g 0 -m "$mode" "$source" "$FF_INSTALL_TEMP"
  mv -T -- "$FF_INSTALL_TEMP" "$destination"
  FF_INSTALL_TEMP=''
}

ff_install() {
  local source_dir=$1 work_dir=$2 target binary revision enable_output
  ff_dependencies curl python3
  for target in /etc/firefighter /var/lib/firefighter /usr/local/bin /etc/firefighter-grokbot \
    /usr/local/bin/firefighter /usr/local/bin/firefighter-grokbot \
    /etc/firefighter/config.json /etc/firefighter/firefighter.env /etc/firefighter/grokbot.env \
    /etc/firefighter-grokbot/config.json /etc/systemd/system/firefighter.service /etc/systemd/system/firefighter-grokbot.service; do
    [[ ! -L "$target" ]] || ff_die "Refusing symlink installation target: $target"
  done
  for target in /etc/firefighter/config.json /etc/firefighter/firefighter.env /etc/firefighter/grokbot.env /etc/firefighter-grokbot/config.json; do
    [[ ! -e "$target" || -f "$target" ]] || ff_die "Expected a regular file: $target"
  done
  python3 "$source_dir/deploy/install-config.py" configure \
    "$source_dir/deploy/firefighter-config.json" \
    /etc/firefighter/config.json /etc/firefighter/firefighter.env \
    "$work_dir/config.json" "$work_dir/firefighter.env"

  ff_select_go "$source_dir" "$work_dir"
  revision=$(git -C "$source_dir" rev-parse --verify HEAD 2>/dev/null || printf source)
  [[ "$revision" =~ ^[0-9a-f]{40}$ || "$revision" == source ]] || ff_die 'Invalid source revision.'
  printf 'Compiling Firefighter from source on this machine.\n'
  (
    cd "$source_dir"
    # Compile for the local machine, independent of inherited cross-build flags.
    unset GOOS GOARCH GOARM GOAMD64 GOROOT GOFLAGS GOEXPERIMENT
    export GOENV=off GOWORK=off GOTOOLCHAIN=local CGO_ENABLED=0
    export TMPDIR="$work_dir/tmp" GOTMPDIR="$work_dir/tmp"
    export GOCACHE="$work_dir/go-cache" GOPATH="$work_dir/go-path" GOMODCACHE="$work_dir/go-modules"
    # Compile one package at a time to keep memory use manageable on small VPSs.
    "$FF_GO" build -p 1 -trimpath -ldflags "-s -w -X main.version=$revision" -o "$work_dir/firefighter" ./cmd/firefighter
    "$FF_GO" build -p 1 -trimpath -ldflags '-s -w' -o "$work_dir/firefighter-grokbot" ./plugins/grokbot/cmd
  )
  # Messaging is the final interactive step. Test it before committing files or
  # starting the service; existing configured upgrades preserve their channel.
  python3 "$source_dir/deploy/install-config.py" configure-report \
    "$work_dir/firefighter" "$work_dir/config.json" "$work_dir/firefighter.env" /etc/firefighter/config.json
  # Validate with credentials in a child environment, never shell-source secrets.
  python3 "$source_dir/deploy/install-config.py" doctor "$work_dir/firefighter" "$work_dir/config.json" "$work_dir/firefighter.env"

  install -d -o 0 -g 0 -m 0700 /etc/firefighter /var/lib/firefighter
  install -d -o 0 -g 0 -m 0755 /usr/local/bin /etc/firefighter-grokbot
  for binary in firefighter firefighter-grokbot; do
    ff_atomic_install "$work_dir/$binary" "/usr/local/bin/$binary" 0755
  done
  ff_atomic_install "$work_dir/config.json" /etc/firefighter/config.json 0600
  ff_atomic_install "$work_dir/firefighter.env" /etc/firefighter/firefighter.env 0600
  if [[ ! -e /etc/firefighter/grokbot.env ]]; then
    install -o 0 -g 0 -m 0600 "$source_dir/deploy/grokbot.env.example" /etc/firefighter/grokbot.env
  fi
  if [[ ! -e /etc/firefighter-grokbot/config.json ]]; then
    install -o 0 -g 0 -m 0644 "$source_dir/plugins/grokbot/config.example.json" /etc/firefighter-grokbot/config.json
  fi
  install -o 0 -g 0 -m 0644 "$source_dir/deploy/firefighter.service" /etc/systemd/system/firefighter.service
  install -o 0 -g 0 -m 0644 "$source_dir/plugins/grokbot/firefighter-grokbot.service" /etc/systemd/system/firefighter-grokbot.service
  systemctl daemon-reload
  if ! enable_output=$(systemctl enable firefighter 2>&1); then
    printf '%s\n' "$enable_output" >&2
    ff_die 'Could not enable Firefighter at boot.'
  fi
  systemctl restart firefighter
  systemctl is-active --quiet firefighter || ff_die 'Firefighter did not stay active. Inspect journalctl -u firefighter before retrying.'
  ff_record_ack
  printf 'Firefighter started as root, autonomous and enabled at boot. Audit: /var/lib/firefighter/audit.jsonl\n'
  printf 'Follow activity: journalctl -u firefighter -f\n'
}
