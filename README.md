# DNSLog-Platform
轻量级 DNS 日志平台，用于 SSRF/联通性验证，内置 DNS 服务器、Web UI 与 REST API。

> 安全提示：请不要将任何包含真实域名、IP、密钥等的配置文件提交到仓库。生产环境配置建议通过环境变量或 `instance/config.json` 提供。

## 功能特性
- 内置权威 DNS 服务（A/NS 记录可配置）
- Web 管理界面：日志查看、会话管理、系统设置
- REST API：会话、子域名生成、日志查询、统计信息
- API Token 管理（Bearer Token）
- 日志保留策略（启动时自动清理）
- Prometheus 指标 `/metrics`

## 目录结构
```
SSRF/
├─ python/               # 应用代码（Flask）
│  ├─ app/               # 业务逻辑、API、模板
│  ├─ run.py             # 开发运行入口
│  └─ requirements.txt   # 依赖
├─ scripts/              # 启停脚本（gunicorn + 后台 DNS 线程）
├─ logs/                 # 运行日志（已被 .gitignore 忽略）
├─ run/                  # 进程 PID 文件（已被 .gitignore 忽略）
├─ instance/             # 实例配置（已被 .gitignore 忽略）
└─ LICENSE
```

## 环境要求
- 操作系统：Linux（建议）
- Python：3.8+
- 端口：
  - DNS：默认 53（需要 root 或赋予 `cap_net_bind_service`）
  - Web：默认 8000

## 安装
```bash
git clone <your-repo-url>
cd SSRF/python

# 创建虚拟环境（可选）
python3 -m venv .venv
source .venv/bin/activate

# 安装依赖
pip install -U pip
pip install -r requirements.txt
```

## 配置
系统支持通过「环境变量」或 `instance/config.json` 覆盖配置。二者键名与含义一致，后者示例见下。

可用环境变量（括号内为默认值）：
- `SECRET_KEY`（please-change-me-in-production）：Flask 密钥
- `DATABASE_URL`（sqlite:///dnslog.db）：数据库连接串
- `DNS_SERVER_HOST`（0.0.0.0）/ `DNS_SERVER_PORT`（53）：DNS 监听
- `WEB_SERVER_HOST`（0.0.0.0）/ `WEB_SERVER_PORT`（8000）：Web 监听
- `DOMAIN`（example.com）：主域名
- `NS1_DOMAIN`（ns1.example.com）/ `NS2_DOMAIN`（ns2.example.com）：NS 域名
- `NS_IP`（127.0.0.1）：NS A 记录 IP
- `A_RECORD_IP`（127.0.0.1）：普通子域名返回的 IP
- `LOG_RETENTION_DAYS`（7）：日志保留天数
- `ADMIN_PASSWORD`（未设置则为 123456）：默认管理员初始口令

`instance/config.json` 示例（优先于类默认值，与环境变量含义一致）：
```json
{
  "DOMAIN": "example.com",
  "NS1_DOMAIN": "ns1.example.com",
  "NS2_DOMAIN": "ns2.example.com",
  "NS_IP": "127.0.0.1",
  "A_RECORD_IP": "127.0.0.1",
  "DNS_SERVER_HOST": "0.0.0.0",
  "DNS_SERVER_PORT": 53,
  "WEB_SERVER_HOST": "0.0.0.0",
  "WEB_SERVER_PORT": 8000,
  "SQLALCHEMY_DATABASE_URI": "sqlite:///dnslog.db",
  "LOG_RETENTION_DAYS": 7
}
```

> 环境变量示例可参考 `.env.example`（不要提交真实机密）。

## 运行
方式 A（开发）：
```bash
cd SSRF/python
python3 run.py
# Web:  http://<WEB_SERVER_HOST>:<WEB_SERVER_PORT>
# API:  http://<WEB_SERVER_HOST>:<WEB_SERVER_PORT>/api
```

方式 B（服务）：
```bash
# 启动（后台运行 gunicorn 与 DNS 线程）
bash scripts/start.sh

# 停止
bash scripts/stop.sh

# 查看日志
ls -l logs/
```

## 管理员账户
- 首次启动会自动创建管理员 `admin`
- 密码来源：环境变量 `ADMIN_PASSWORD`，若未设置则为 `123456`
- 可在 Web → 右上角「用户资料」修改密码

命令行管理（位于 `python/manage_users.py`）：
```bash
# 查看用户
python3 python/manage_users.py list-users

# 创建用户（交互式输入密码）
python3 python/manage_users.py create-user --admin

# 修改密码（交互式输入新密码）
python3 python/manage_users.py change-password --username <user>

# 启用/停用用户
python3 python/manage_users.py toggle-user --username <user> --active/--inactive

# 赋予/取消管理员
python3 python/manage_users.py set-admin --username <user> --admin/--no-admin

# 重置默认管理员（密码将重置为 123456）
python3 python/manage_users.py reset-admin
```

## API 快速体验
打开 Web 界面中的「API 文档」页面（/api）可直接测试；或使用 curl：
```bash
# 生成子域名（需登录会话或 Bearer Token）
curl -X POST http://<host>:<port>/api/subdomain/generate \
  -H "Content-Type: application/json" \
  -d '{"type":"ssrf","length":12}'

# 检查子域名是否有日志
curl http://<host>:<port>/api/logs/check/<subdomain>

# 获取统计信息
curl http://<host>:<port>/api/stats
```

## 监控指标
- 访问 `/metrics` 获取 Prometheus 指标（若 `prometheus_client` 可用）

## 安全建议（强烈建议）
- 生产环境务必设置强 `SECRET_KEY` 与强 `ADMIN_PASSWORD`
- 不要暴露管理端口与 API 到公网，或至少加防火墙限制
- DNS 端口 53 需要 root 权限；或使用非 53 端口并在外部负载/网关层做映射
- 定期清理历史日志与检查登录行为
- 切勿将 `.env`、`instance/`、数据库、证书、日志等提交到仓库

## 常见问题
1) 53 端口权限错误：
```
请以 root 运行，或将 DNS_SERVER_PORT 改为 >1024 端口；
也可为 Python 进程二进制赋予 cap_net_bind_service 能力。
```

2) 端口占用：
```
根据日志提示，关闭占用进程或修改 WEB/DNS 端口后重试。
```

## 许可证
本项目基于 GPL-3.0 许可，详见 `LICENSE`。
