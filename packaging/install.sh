#!/usr/bin/env sh
set -eu

# Install the release tarball's caddyui binary and systemd unit.
# Run from inside the extracted release directory:
#   ./install.sh

if [ "$(id -u)" -eq 0 ]; then
  sudo_cmd=""
else
  sudo_cmd="sudo"
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary="${script_dir}/caddyui"
service="${script_dir}/caddyui.service"

if [ ! -f "${binary}" ]; then
  echo "error: caddyui binary not found at ${binary}" >&2
  exit 1
fi

if [ ! -f "${service}" ]; then
  echo "error: caddyui.service not found at ${service}" >&2
  exit 1
fi

if ! id -u caddyui >/dev/null 2>&1; then
  ${sudo_cmd} useradd --system --home /var/lib/caddyui --shell /usr/sbin/nologin caddyui
fi

${sudo_cmd} install -d -o caddyui -g caddyui -m 0750 /var/lib/caddyui
${sudo_cmd} install -m 0755 "${binary}" /usr/local/bin/caddyui
${sudo_cmd} install -m 0644 "${service}" /etc/systemd/system/caddyui.service
${sudo_cmd} systemctl daemon-reload
${sudo_cmd} systemctl enable --now caddyui

echo "CaddyUI installed and started."
echo "Check status with: systemctl status caddyui"
