from flask import Flask
from flask_cors import CORS
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from app.config import Config, load_instance_overrides
from app.models import db, User, DNSLog, LoginSecurity
from app.api import api_bp, web_bp
from app.dns_server import create_dns_server
from sqlalchemy import text
from sqlalchemy import event
import time
import logging
import os

csrf = CSRFProtect()

def create_app():
    """创建Flask应用"""
    app = Flask(__name__)
    app.config.from_object(Config)
    # Instance overrides (instance/config.json)
    try:
        load_instance_overrides(app.config, app.instance_path)
    except Exception:
        pass
    
    # 设置日志
    logging.basicConfig(level=logging.INFO)
    
    # 初始化扩展
    db.init_app(app)
    CORS(app)
    # CSRF for forms; API以Bearer/会话鉴权为主，可选择豁免
    csrf.init_app(app)
    
    # 初始化Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = '请先登录访问此页面'
    login_manager.login_message_category = 'warning'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # 注册蓝图
    app.register_blueprint(api_bp)
    app.register_blueprint(web_bp)
    
    # 注册认证蓝图
    from app.auth import auth_bp
    app.register_blueprint(auth_bp)
    try:
        # CSRF 豁免：API 与认证蓝图（登录JSON、API均不使用表单CSRF）
        csrf.exempt(api_bp)
        csrf.exempt(auth_bp)
    except Exception:
        pass
    
    # 创建数据库表
    with app.app_context():
        # SQLite PRAGMA tuning (WAL, synchronous)
        try:
            from sqlalchemy import inspect
            engine = db.get_engine()
            with engine.connect() as conn:
                conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
                conn.exec_driver_sql("PRAGMA synchronous=NORMAL;")
                conn.exec_driver_sql("PRAGMA wal_autocheckpoint=1000;")
        except Exception as e:
            logging.warning(f"SQLite PRAGMA 设置失败: {e}")
        db.create_all()
        # 创建默认管理员用户
        User.create_admin_user()
        # 创建索引（如不存在）
        try:
            # 函数索引：lower(subdomain)
            db.session.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_dns_logs_subdomain_lower
                ON dns_logs (lower(subdomain));
            """))
            # 组合索引：session_id, timestamp
            db.session.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_dns_logs_session_ts
                ON dns_logs (session_id, timestamp);
            """))
            # 单列索引：client_ip（如未建）
            db.session.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_dns_logs_client_ip
                ON dns_logs (client_ip);
            """))
            db.session.commit()
        except Exception as e:
            logging.warning(f"创建索引失败: {e}")
            try:
                db.session.rollback()
            except Exception:
                pass
        # 确保每个用户有登录安全记录
        try:
            for user in User.query.all():
                if not LoginSecurity.query.filter_by(user_id=user.id).first():
                    sec = LoginSecurity(user_id=user.id)
                    db.session.add(sec)
            db.session.commit()
        except Exception as e:
            logging.warning(f"初始化登录安全记录失败: {e}")
        # 启动时清理过期日志
        try:
            from datetime import datetime, timedelta
            cutoff = datetime.utcnow() - timedelta(days=Config.LOG_RETENTION_DAYS)
            deleted = db.session.query(DNSLog).filter(DNSLog.timestamp < cutoff).delete()
            if deleted:
                db.session.commit()
                logging.info(f"已清理过期日志 {deleted} 条（>{Config.LOG_RETENTION_DAYS} 天）")
        except Exception as e:
            logging.warning(f"启动时日志清理失败: {e}")
    
    # 创建DNS服务器
    dns_server = create_dns_server(app)
    app.dns_server = dns_server

    # Prometheus /metrics 端点
    try:
        from prometheus_client import Counter, Summary, generate_latest, CONTENT_TYPE_LATEST
        from flask import Response, g, request

        HTTP_REQUESTS = Counter(
            'dnslog_http_requests_total', 'HTTP requests', ['endpoint', 'method', 'status']
        )
        HTTP_LATENCY = Summary(
            'dnslog_http_request_seconds', 'HTTP request duration seconds', ['endpoint', 'method']
        )

        @app.before_request
        def _metrics_before():
            g._req_start_ns = time.time()

        @app.after_request
        def _metrics_after(resp):
            try:
                endpoint = request.endpoint or 'unknown'
                method = request.method
                status = str(resp.status_code)
                HTTP_REQUESTS.labels(endpoint=endpoint, method=method, status=status).inc()
                if hasattr(g, '_req_start_ns'):
                    HTTP_LATENCY.labels(endpoint=endpoint, method=method).observe(max(0.0, time.time() - g._req_start_ns))
            except Exception:
                pass
            return resp

        @app.route('/metrics')
        def metrics():
            data = generate_latest()
            return Response(data, mimetype=CONTENT_TYPE_LATEST)
    except Exception as e:
        logging.warning(f"Prometheus指标未启用: {e}")
    
    return app
