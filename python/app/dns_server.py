import socket
import threading
import os
from datetime import datetime
from dnslib import DNSRecord, DNSHeader, RR, A, NS, QTYPE
from dnslib.server import DNSServer, BaseResolver
from app.models import db, DNSLog, Session
from app.config import Config
import logging
try:
    from prometheus_client import Counter
    DNS_QUERIES = Counter('dnslog_dns_queries_total', 'Total DNS queries', ['qtype'])
    DNS_QUERIES_IN_DOMAIN = Counter('dnslog_dns_queries_in_domain_total', 'DNS queries under managed domain')
    DNS_QUERIES_OUT_DOMAIN = Counter('dnslog_dns_queries_out_domain_total', 'DNS queries outside managed domain')
    DNS_RATE_LIMIT_DROPS = Counter('dnslog_dns_rate_limited_total', 'DNS queries dropped by rate limit')
except Exception:
    DNS_QUERIES = None
    DNS_QUERIES_IN_DOMAIN = None
    DNS_QUERIES_OUT_DOMAIN = None
    DNS_RATE_LIMIT_DROPS = None

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DNSLogResolver(BaseResolver):
    """自定义DNS解析器，记录所有查询"""
    
    def __init__(self, app):
        self.app = app
        self.domain = Config.DOMAIN
        self.ns_ip = Config.NS_IP
        self.a_record_ip = Config.A_RECORD_IP
        
    # 简单速率限制（按IP与秒级粒度）
    _rate_window = {}
    _max_per_sec = 200

    def resolve(self, request, handler):
        """处理DNS查询并记录到数据库"""
        reply = request.reply()
        qname = str(request.q.qname).rstrip('.')
        qtype = QTYPE[request.q.qtype]
        client_ip = handler.client_address[0]
        
        logger.info(f"DNS查询: {qname} ({qtype}) from {client_ip}")
        try:
            if DNS_QUERIES: DNS_QUERIES.labels(qtype=qtype).inc()
        except Exception:
            pass
        
        # 速率限制
        try:
            key = (client_ip, int(datetime.utcnow().timestamp()))
            self._rate_window[key] = self._rate_window.get(key, 0) + 1
            if self._rate_window[key] > self._max_per_sec:
                logger.warning(f"Rate limit exceeded from {client_ip}")
                try:
                    if DNS_RATE_LIMIT_DROPS: DNS_RATE_LIMIT_DROPS.inc()
                except Exception:
                    pass
                return reply  # 丢弃额外响应
        except Exception:
            pass

        # 定期清理速率窗口（只保留最近2秒）
        try:
            cutoff = int(datetime.utcnow().timestamp()) - 2
            if len(self._rate_window) > 10000:
                self._rate_window = {k: v for k, v in self._rate_window.items() if k[1] >= cutoff}
        except Exception:
            pass
        
        try:
            # 非目标主域名：不记录并返回 NXDOMAIN
            in_domain = (qname == self.domain or qname.endswith(f'.{self.domain}'))
            try:
                if in_domain:
                    if DNS_QUERIES_IN_DOMAIN: DNS_QUERIES_IN_DOMAIN.inc()
                else:
                    if DNS_QUERIES_OUT_DOMAIN: DNS_QUERIES_OUT_DOMAIN.inc()
            except Exception:
                pass
            if not in_domain:
                reply.header.rcode = 3  # NXDOMAIN
                return reply

            # 处理不同类型的DNS查询
            if qtype == 'A':
                self._handle_a_record(reply, qname)
            elif qtype == 'NS':
                self._handle_ns_record(reply, qname)
            elif qtype == 'ANY':
                self._handle_any_record(reply, qname)
            else:
                # 对于其他类型的查询，返回A记录
                self._handle_a_record(reply, qname)
            
            # 仅对本域记录到数据库（放在成功构造响应之后）
            self._log_dns_query(qname, qtype, client_ip)
                
        except Exception as e:
            logger.error(f"DNS解析错误: {e}")
            
        return reply
    
    def _log_dns_query(self, qname, qtype, client_ip):
        """记录DNS查询到数据库"""
        try:
            with self.app.app_context():
                # 解析域名结构（规范化：去除重复域名后缀，大小写不敏感）
                left = qname
                left_lower = left.lower()
                domain_lower = self.domain.lower()
                while True:
                    if left_lower == domain_lower:
                        left = ''
                        break
                    suffix = '.' + domain_lower
                    if left_lower.endswith(suffix):
                        # 去掉一次域名后缀
                        left = left[:-(len(self.domain) + 1)]
                        left_lower = left.lower()
                        continue
                    break
                subdomain = left if left else '@'
                
                # 创建DNS日志记录
                dns_log = DNSLog(
                    subdomain=subdomain,
                    domain=self.domain,
                    client_ip=client_ip,
                    query_type=qtype,
                    timestamp=datetime.utcnow()
                )
                
                # 尝试从子域名中提取会话ID
                session_id = self._extract_session_id(subdomain)
                if session_id:
                    dns_log.session_id = session_id
                
                db.session.add(dns_log)
                db.session.commit()
                # 更新会话活跃时间
                if session_id:
                    try:
                        Session.touch(session_id)
                    except Exception:
                        try:
                            db.session.rollback()
                        except Exception:
                            pass
                
                logger.info(f"DNS查询已记录: {subdomain}.{self.domain}")
                
        except Exception as e:
            logger.error(f"记录DNS查询失败: {e}")
            try:
                db.session.rollback()
            except:
                pass
    
    def _extract_session_id(self, subdomain):
        """从子域名中提取会话ID"""
        try:
            parts = subdomain.split('-')
            # 1) 完整32位十六进制（无连字符）
            for part in parts:
                if len(part) >= 32 and all(c in '0123456789abcdef' for c in part.lower()):
                    if len(part) == 32:
                        uuid_str = f"{part[:8]}-{part[8:12]}-{part[12:16]}-{part[16:20]}-{part[20:]}"
                        return uuid_str
            # 2) 兼容当前生成策略：使用会话ID前8位作为前缀
            if parts and len(parts[0]) == 8 and all(c in '0123456789abcdef' for c in parts[0].lower()):
                prefix8 = parts[0].lower()
                with self.app.app_context():
                    # 在SQL中移除连字符后进行前缀匹配
                    candidate = Session.query.filter(
                        db.func.lower(db.func.replace(Session.id, '-', '')).like(prefix8 + '%')
                    ).order_by(Session.created_at.desc()).first()
                    if candidate:
                        return candidate.id
            return None
        except:
            return None
    
    def _handle_a_record(self, reply, qname):
        """处理A记录查询"""
        # 特殊处理NS记录的A查询
        if qname == Config.NS1_DOMAIN or qname == Config.NS2_DOMAIN:
            # NS服务器返回DNS服务器的IP
            reply.add_answer(RR(qname, 1, rdata=A(self.ns_ip), ttl=60))
        else:
            # 其他子域名返回配置的IP地址
            reply.add_answer(RR(qname, 1, rdata=A(self.a_record_ip), ttl=60))
    
    def _handle_ns_record(self, reply, qname):
        """处理NS记录查询"""
        if qname == self.domain or qname.endswith(f'.{self.domain}'):
            reply.add_answer(RR(qname, 2, rdata=NS(Config.NS1_DOMAIN), ttl=3600))
            reply.add_answer(RR(qname, 2, rdata=NS(Config.NS2_DOMAIN), ttl=3600))
    
    def _handle_any_record(self, reply, qname):
        """处理ANY记录查询"""
        self._handle_a_record(reply, qname)
        self._handle_ns_record(reply, qname)

class DNSLogServer:
    """DNS日志服务器"""
    
    def __init__(self, app):
        self.app = app
        self.server = None
        self.resolver = DNSLogResolver(app)
        # 在运行时重新读取配置，以支持环境变量覆盖
        self.host = os.environ.get('DNS_SERVER_HOST', Config.DNS_SERVER_HOST)
        self.port = int(os.environ.get('DNS_SERVER_PORT', Config.DNS_SERVER_PORT))
        
    def start(self):
        """启动DNS服务器"""
        try:
            logger.info(f"启动DNS服务器在 {self.host}:{self.port}")
            self.server = DNSServer(
                resolver=self.resolver,
                port=self.port,
                address=self.host,
                tcp=False  # 使用UDP
            )
            self.server.start()
            logger.info("DNS服务器启动成功")
        except Exception as e:
            logger.error(f"DNS服务器启动失败: {e}")
            raise
    
    def start_threaded(self):
        """在新线程中启动DNS服务器"""
        def run_server():
            try:
                self.start()
            except Exception as e:
                logger.error(f"DNS服务器线程错误: {e}")
        
        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()
        logger.info("DNS服务器已在后台线程启动")
        return thread
    
    def stop(self):
        """停止DNS服务器"""
        if self.server:
            try:
                self.server.stop()
                logger.info("DNS服务器已停止")
            except Exception as e:
                logger.error(f"停止DNS服务器失败: {e}")

def create_dns_server(app):
    """创建DNS服务器实例"""
    return DNSLogServer(app)
