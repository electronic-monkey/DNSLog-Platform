# DNSLog-Platform
轻量级 DNS 日志平台，用于 SSRF/联通性验证，内置 DNS 服务器、Web UI 与 REST API。

项目地址：`https://github.com/electronic-monkey/DNSLog-Platform`

项目地址：`https://github.com/electronic-monkey/DNSLog-Platform`

## 界面预览
首页
<img width="2556" height="1383" alt="70ac7e1ccafdd894f8be5749b4b9d6d3" src="https://github.com/user-attachments/assets/bb4872b0-0d82-494e-8e01-79d79ed27b0b" />
日志
<img width="2559" height="1362" alt="806f59e7aa042ce26959b45a73841dc8" src="https://github.com/user-attachments/assets/f6e5aa5b-fa8e-4998-b47a-26ec1bb0262a" />
系统设置
<img width="2559" height="1368" alt="8289182a66d7ec5784ef89a4ab1fe27a" src="https://github.com/user-attachments/assets/f52b9cf1-d30a-47d4-a7be-101158bfddf9" />


## 功能特性
- 内置权威 DNS 服务（A/NS 记录可配置）
- Web 管理界面：日志查看、会话管理、系统设置
- REST API：会话、子域名生成、日志查询、统计信息
- API Token 管理（Bearer Token）
- 用户管理（管理员）：创建用户、启/停用、设/撤管理员、重置密码、删除
- 生成白名单：仅记录“通过平台生成”的子域名的 DNS 查询
- 系统设置保存即应用（DNS 解析实时生效；Web 监听变更需用新地址访问）
- 深色模式（右上角切换，自动记忆）
- 日志保留策略（启动时自动清理）
- Prometheus 指标 `/metrics`

## 目录结构
```
SSRF/
├─ python/                          # 应用根目录
│  ├─ app/                          # 应用核心
│  │  ├─ __init__.py               # create_app、扩展初始化、WAL/索引、指标
│  │  ├─ api.py                    # REST API 与 Web 路由
│  │  ├─ auth.py                   # 登录/登出、Token、用户管理（管理员）
│  │  ├─ dns_server.py             # 内置权威 DNS 服务器与解析逻辑
│  │  ├─ models.py                 # ORM 模型（日志/会话/用户/Token/白名单等）
│  │  ├─ config.py                 # 配置与 instance/config.json 覆盖
│  │  ├─ templates/                # 前端模板（首页/日志/会话/设置/认证等）
│  │  └─ static/                   # 前端静态资源
│  ├─ run.py                       # 开发运行入口（含横幅与组件启动）
│  ├─ app.py                       # WSGI 入口（python3 app.py）
│  └─ requirements.txt             # 依赖
├─ scripts/                         # 启停脚本（gunicorn + DNS 线程）
│  ├─ start.sh
│  └─ stop.sh
├─ instance/                        # 运行时实例目录（config.json 等）
├─ logs/                            # 运行日志目录
├─ run/                             # 运行时 PID 目录
├─ README.md                        # 项目说明
└─ LICENSE                          # 许可证
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
