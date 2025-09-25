#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)
APP_DIR="$ROOT_DIR/python"
PID_DIR="$ROOT_DIR/run"
LOG_DIR="$ROOT_DIR/logs"
WEB_PID_FILE="$PID_DIR/web.pid"
DNS_PID_FILE="$PID_DIR/dns.pid"

mkdir -p "$PID_DIR" "$LOG_DIR"

if [[ -f "$WEB_PID_FILE" ]] && kill -0 "$(cat "$WEB_PID_FILE")" 2>/dev/null; then
  echo "Web 已在运行 (PID $(cat "$WEB_PID_FILE"))"
  exit 0
fi

if [[ -f "$DNS_PID_FILE" ]] && kill -0 "$(cat "$DNS_PID_FILE")" 2>/dev/null; then
  echo "DNS 已在运行 (PID $(cat "$DNS_PID_FILE"))"
else
  echo "启动 DNS 服务器..."
  (
    cd "$APP_DIR"
    nohup python3 -c "from app import create_app; app = create_app(); app.dns_server.start_threaded(); import time; time.sleep(999999)" \
      > "$LOG_DIR/dns_server.log" 2>&1 &
    echo $! > "$DNS_PID_FILE"
  )
  echo "DNS 启动完成 (PID $(cat "$DNS_PID_FILE"))"
fi

echo "启动 Web (gunicorn)..."
(
  cd "$APP_DIR"
  nohup gunicorn -c gunicorn.conf.py 'app:create_app()' \
    > "$LOG_DIR/web_server.log" 2>&1 &
  echo $! > "$WEB_PID_FILE"
)
echo "Web 启动完成 (PID $(cat "$WEB_PID_FILE"))"

echo "所有服务已启动。日志目录: $LOG_DIR"
