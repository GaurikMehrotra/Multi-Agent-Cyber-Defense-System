#!/usr/bin/env bash
# Reproduce dependencies and build isolated lab images; never create a worktree.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
task_venv=/workspace/venvs/cyber-defense
export PIP_CACHE_DIR=/workspace/.cache/pip
export XDG_CACHE_HOME=/workspace/.cache
export MPLCONFIGDIR=/workspace/.cache/matplotlib
export DOCKER_CONFIG=/workspace/.docker
mkdir -p "$PIP_CACHE_DIR" "$MPLCONFIGDIR" "$DOCKER_CONFIG"
if [[ ! -x "$task_venv/bin/python" ]]; then
  python3.12 -m venv "$task_venv"
fi
"$task_venv/bin/python" -m pip install --upgrade pip==26.2.1
"$task_venv/bin/python" -m pip install -r requirements.txt
"$task_venv/bin/python" -m pip check
if [[ ! -f .env ]]; then
  "$task_venv/bin/python" scripts/init_env.py
fi
mkdir -p runtime data/pcaps data/zeek data/suricata artifacts
build_options=()
if [[ -n "${HTTPS_PROXY:-}" || -n "${HTTP_PROXY:-}" ]]; then
  build_options+=(--network host --build-arg HTTP_PROXY --build-arg HTTPS_PROXY)
  task_proxy_host=$("$task_venv/bin/python" -c 'import os; from urllib.parse import urlparse; print(urlparse(os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY", "")).hostname or "")')
  if [[ -n "$task_proxy_host" ]]; then
    task_proxy_ip=$(getent ahostsv4 "$task_proxy_host" | awk 'NR == 1 {print $1; exit}')
    if [[ -n "$task_proxy_ip" ]]; then
      build_options+=(--add-host "$task_proxy_host:$task_proxy_ip")
    fi
  fi
fi
if [[ -n "${SSL_CERT_FILE:-}" && -f "$SSL_CERT_FILE" ]]; then
  build_options+=(--secret "id=proxy_ca,src=$SSL_CERT_FILE")
fi
# Build-time host networking applies only to dependency installation, never the lab runtime.
docker build "${build_options[@]}" -f docker/Dockerfile -t cyber-defense-app:dev .
docker build "${build_options[@]}" -f docker/Dockerfile.nmap -t cyber-defense-nmap:dev .
docker build "${build_options[@]}" -f lab/Dockerfile.traffic -t cyber-defense-traffic:dev .
docker pull zeek/zeek:7.0.4@sha256:a6492105946f483606ee2c907a6881c6d9ae18a1d0e9171cde0b30355d57a9da
docker pull jasonish/suricata:7.0.8@sha256:89b300fb5d00f182359a1305543e828a804ede7f1685e75b05f607f7372428c6
export PATH="$task_venv/bin:$PATH"
make lint test
