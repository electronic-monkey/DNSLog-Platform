#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)
PID_DIR="$ROOT_DIR/run"
WEB_PID_FILE="$PID_DIR/web.pid"
DNS_PID_FILE="$PID_DIR/dns.pid"

stop_pid() {
  local pid_file="$1"
  local name="$2"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid=$(cat "$pid_file")
    if kill -0 "$pid" 2>/dev/null; then
      echo "停止 $name (PID $pid)..."
      kill -TERM "$pid" 2>/dev/null || true
      sleep 1
      if kill -0 "$pid" 2>/dev/null; then
        echo "$name 未及时退出，强制终止..."
        kill -KILL "$pid" 2>/dev/null || true
      fi
    fi
    rm -f "$pid_file"
  else
    echo "$name 未在运行"
  fi
}

stop_pid "$WEB_PID_FILE" "Web (gunicorn)"
stop_pid "$DNS_PID_FILE" "DNS"

echo "所有服务已停止。"
