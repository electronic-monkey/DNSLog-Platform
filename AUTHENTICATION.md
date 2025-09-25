# DNSLog Platform 认证系统

## 概述

DNSLog Platform 现已集成完整的用户认证系统，提供安全的管理员访问控制。

## 功能特性

- **用户认证**: 基于Flask-Login的会话管理
- **密码安全**: 使用Werkzeug的密码哈希加密
- **会话管理**: 支持"记住我"功能
- **权限控制**: 管理员权限管理
- **安全防护**: 所有管理页面需要登录访问

## 默认管理员账户

系统会自动创建默认管理员账户：
- **用户名**: admin
- **密码**: 123456Test.
- **权限**: 管理员

⚠️ **安全提醒**: 首次登录后请立即修改默认密码！

## 访问系统

1. 访问平台首页: `http://your-server:5000/`
2. 系统会自动重定向到登录页面: `/auth/login`
3. 输入管理员凭据进行登录
4. 登录成功后可访问所有管理功能

## 页面保护

以下页面需要登录后才能访问：
- `/` - 主页和DNS日志管理
- `/logs` - DNS日志查看
- `/sessions` - 会话管理
- `/api` - API文档

## 用户管理

### 使用管理脚本

系统提供了命令行用户管理工具 `manage_users.py`：

```bash
# 查看所有用户
python3 manage_users.py list-users

# 创建新用户
python3 manage_users.py create-user

# 创建管理员用户
python3 manage_users.py create-user --admin

# 删除用户
python3 manage_users.py delete-user

# 修改密码
python3 manage_users.py change-password

# 激活/停用用户
python3 manage_users.py toggle-user

# 设置管理员权限
python3 manage_users.py set-admin

# 重置默认管理员账户
python3 manage_users.py reset-admin
```

### 通过Web界面

登录后可以通过以下方式管理账户：
1. 点击右上角用户名 → "用户资料"
2. 在资料页面可以修改密码
3. 查看账户信息和登录历史

## API认证

### 检查认证状态

```bash
GET /auth/api/check-auth
```

响应:
```json
{
  "authenticated": true,
  "user": {
    "id": 1,
    "username": "admin",
    "is_admin": true,
    "is_active": true,
    "created_at": "2025-09-25T07:18:37.558354",
    "last_login": "2025-09-25T07:25:37.797272"
  }
}
```

### 获取当前用户信息

```bash
GET /auth/api/current-user
```

需要登录，返回当前用户详细信息。

### API登录

```bash
POST /auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your-password",
  "remember_me": false
}
```

## 安全最佳实践

1. **立即修改默认密码**: 首次部署后必须修改默认管理员密码
2. **使用强密码**: 密码应包含大小写字母、数字和特殊字符
3. **定期更换密码**: 建议定期更新管理员密码
4. **限制访问**: 建议使用防火墙限制管理端口访问
5. **监控登录**: 定期检查登录日志，发现异常及时处理

## 故障排除

### 忘记密码

使用管理脚本重置密码：

```bash
# 重置特定用户密码
python3 manage_users.py change-password --username admin

# 重置默认管理员账户
python3 manage_users.py reset-admin
```

### 登录问题

1. 检查用户是否被停用：
   ```bash
   python3 manage_users.py list-users
   ```

2. 激活用户：
   ```bash
   python3 manage_users.py toggle-user --username admin --active
   ```

### 数据库问题

如果用户表损坏，可以重新创建：

```bash
# 进入Python交互环境
python3 -c "
from app import create_app
from app.models import db, User
app = create_app()
with app.app_context():
    db.create_all()
    User.create_admin_user()
    print('用户表已重建，默认管理员账户已创建')
"
```

## 技术细节

- **框架**: Flask + Flask-Login
- **密码加密**: Werkzeug PBKDF2
- **会话存储**: Flask Session (服务器端)
- **数据库**: SQLite (可配置其他数据库)
- **前端**: Bootstrap 5 + 原生JavaScript

## 配置选项

在 `app/config.py` 中可以配置：

```python
# Session配置
SECRET_KEY = 'your-secret-key'  # 生产环境必须修改

# 数据库配置
SQLALCHEMY_DATABASE_URI = 'sqlite:///dnslog.db'  # 或其他数据库
```

环境变量：
- `SECRET_KEY`: Flask密钥，用于会话加密
- `DATABASE_URL`: 数据库连接字符串
