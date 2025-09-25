from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import hashlib
import uuid
import string
import random

db = SQLAlchemy()

class DNSLog(db.Model):
    """DNS查询日志模型"""
    __tablename__ = 'dns_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    # DNS查询信息
    subdomain = db.Column(db.String(255), nullable=False, index=True)
    domain = db.Column(db.String(255), nullable=False)
    client_ip = db.Column(db.String(45), nullable=False)  # 支持IPv6
    query_type = db.Column(db.String(10), nullable=False)  # A, AAAA, NS, TXT等
    
    # 时间戳
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # 用户标识（用于区分不同的测试会话）
    session_id = db.Column(db.String(36), nullable=True, index=True)
    
    # 附加信息
    user_agent = db.Column(db.Text, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<DNSLog {self.subdomain}.{self.domain} from {self.client_ip}>'
    
    def to_dict(self):
        """转换为字典格式，用于API返回"""
        return {
            'id': self.id,
            'subdomain': self.subdomain,
            'subdomain_normalized': (self.subdomain or '').lower(),
            'domain': self.domain,
            'full_domain': f"{self.subdomain}.{self.domain}",
            'full_domain_normalized': f"{(self.subdomain or '').lower()}.{(self.domain or '').lower()}",
            'client_ip': self.client_ip,
            'query_type': self.query_type,
            'timestamp': self.timestamp.isoformat(),
            'session_id': self.session_id,
            'user_agent': self.user_agent,
            'notes': self.notes
        }

class Session(db.Model):
    """测试会话模型"""
    __tablename__ = 'sessions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # 关联的DNS日志
    dns_logs = db.relationship('DNSLog', backref='session_info', 
                              foreign_keys='DNSLog.session_id',
                              primaryjoin='Session.id == DNSLog.session_id')
    
    def __repr__(self):
        return f'<Session {self.id}: {self.name}>'
    
    def to_dict(self):
        """转换为字典格式，用于API返回"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'dns_logs_count': len(self.dns_logs)
        }

class SubdomainGenerator:
    """子域名生成器"""
    
    @staticmethod
    def generate_random_subdomain(length=12):
        """生成随机子域名"""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    @staticmethod
    def generate_session_subdomain(session_id, suffix=""):
        """为特定会话生成子域名"""
        # 使用会话ID的前8位 + 随机后缀
        session_prefix = session_id.replace('-', '')[:8]
        random_suffix = SubdomainGenerator.generate_random_subdomain(4)
        if suffix:
            return f"{session_prefix}-{suffix}-{random_suffix}"
        return f"{session_prefix}-{random_suffix}"
    
    @staticmethod
    def generate_payload_subdomain(payload_type, session_id=""):
        """根据payload类型生成子域名"""
        payload_map = {
            'ssrf': 'ssrf',
            'rce': 'rce',
            'lfi': 'lfi',
            'sqli': 'sql',
            'xss': 'xss',
            'xxe': 'xxe'
        }
        prefix = payload_map.get(payload_type, 'test')
        
        if session_id:
            return SubdomainGenerator.generate_session_subdomain(session_id, prefix)
        else:
            random_suffix = SubdomainGenerator.generate_random_subdomain(8)
            return f"{prefix}-{random_suffix}"

class User(UserMixin, db.Model):
    """用户模型"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        """设置密码"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """转换为字典格式"""
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active
        }
    
    @staticmethod
    def create_admin_user(username='admin', password=None):
        """创建默认管理员用户"""
        # 检查用户是否已存在
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return existing_user
        
        # 创建新管理员用户
        admin_user = User(
            username=username,
            is_admin=True,
            is_active=True
        )
        # 若未设置密码，使用环境变量 ADMIN_PASSWORD 或默认 123456
        if not password:
            import os
            password = os.environ.get('ADMIN_PASSWORD') or '123456'
        admin_user.set_password(password)
        
        db.session.add(admin_user)
        db.session.commit()
        
        return admin_user

class APIToken(db.Model):
    """API 访问令牌（仅存储哈希，不落明文）"""
    __tablename__ = 'api_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    scope = db.Column(db.String(64), nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref=db.backref('api_tokens', lazy='dynamic'))

    @staticmethod
    def hash_token(raw_token: str) -> str:
        return hashlib.sha256(raw_token.encode('utf-8')).hexdigest()

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'is_active': self.is_active,
            'scope': self.scope,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }

class LoginSecurity(db.Model):
    """用户登录安全信息（失败计数/锁定时间）。"""
    __tablename__ = 'login_security'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False, index=True)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    last_failed_at = db.Column(db.DateTime, nullable=True)
    locked_until = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref=db.backref('login_security', uselist=False))
