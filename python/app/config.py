import os
from datetime import timedelta

class Config:
    # 数据库配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'please-change-me-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///dnslog.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # DNS服务器配置
    DNS_SERVER_HOST = os.environ.get('DNS_SERVER_HOST') or '0.0.0.0'
    DNS_SERVER_PORT = int(os.environ.get('DNS_SERVER_PORT') or 53)
    
    # Web服务器配置
    WEB_SERVER_HOST = os.environ.get('WEB_SERVER_HOST') or '0.0.0.0'
    WEB_SERVER_PORT = int(os.environ.get('WEB_SERVER_PORT') or 8000)
    
    # 域名配置（根据图片中的配置）
    DOMAIN = os.environ.get('DOMAIN') or 'dns.example.com'
    NS1_DOMAIN = os.environ.get('NS1_DOMAIN') or 'ns1.example.com'
    NS2_DOMAIN = os.environ.get('NS2_DOMAIN') or 'ns2.example.com'
    NS_IP = os.environ.get('NS_IP') or '127.0.0.1'
    A_RECORD_IP = os.environ.get('A_RECORD_IP') or '127.0.0.1'
    
    # 日志保留时间（天）
    LOG_RETENTION_DAYS = int(os.environ.get('LOG_RETENTION_DAYS') or 7)
    
    # API配置
    API_RATE_LIMIT = os.environ.get('API_RATE_LIMIT') or '100 per hour'
    
    # 允许的子域名长度
    SUBDOMAIN_MIN_LENGTH = 8
    SUBDOMAIN_MAX_LENGTH = 32


def load_instance_overrides(app_config, instance_path: str):
    """Load overrides from instance/config.json and apply to Config and app config.

    app_config: Flask.config mapping (app.config)
    instance_path: path to Flask instance folder
    """
    import json
    import os
    cfg_file = os.path.join(instance_path, 'config.json')
    if not os.path.exists(cfg_file):
        return
    try:
        with open(cfg_file, 'r', encoding='utf-8') as f:
            data = json.load(f) or {}
        # Map known keys
        mapping = {
            'DOMAIN': 'DOMAIN',
            'NS1_DOMAIN': 'NS1_DOMAIN',
            'NS2_DOMAIN': 'NS2_DOMAIN',
            'NS_IP': 'NS_IP',
            'A_RECORD_IP': 'A_RECORD_IP',
            'DNS_SERVER_HOST': 'DNS_SERVER_HOST',
            'DNS_SERVER_PORT': 'DNS_SERVER_PORT',
            'WEB_SERVER_HOST': 'WEB_SERVER_HOST',
            'WEB_SERVER_PORT': 'WEB_SERVER_PORT',
            'SQLALCHEMY_DATABASE_URI': 'SQLALCHEMY_DATABASE_URI',
            'LOG_RETENTION_DAYS': 'LOG_RETENTION_DAYS',
        }
        for k_json, attr in mapping.items():
            if k_json in data and data[k_json] is not None:
                # update class attribute
                setattr(Config, attr, data[k_json] if attr not in ('DNS_SERVER_PORT','WEB_SERVER_PORT','LOG_RETENTION_DAYS') else int(data[k_json]))
                # update app.config
                app_config[attr] = getattr(Config, attr)
    except Exception:
        # ignore malformed overrides
        pass
