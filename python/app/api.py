from flask import Blueprint, request, jsonify, render_template, abort
from flask import Response
from flask_cors import cross_origin
from flask import current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from app.models import db, DNSLog, Session, SubdomainGenerator, APIToken, GeneratedSubdomain
from app.config import Config
import os, json
import uuid
import logging

logger = logging.getLogger(__name__)

# 创建API蓝图
api_bp = Blueprint('api', __name__)
web_bp = Blueprint('web', __name__)

# ==================== API接口 ====================

@api_bp.route('/api/session', methods=['POST'])
@cross_origin()
def create_session():
    """创建新的测试会话"""
    try:
        if not _require_api_auth():
            return jsonify({'success': False, 'message': '未授权'}), 401
        data = request.get_json() or {}
        session_id = str(uuid.uuid4())
        
        session = Session(
            id=session_id,
            name=data.get('name', f'Session-{datetime.now().strftime("%Y%m%d-%H%M%S")}'),
            description=data.get('description', '')
        )
        
        db.session.add(session)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'session': session.to_dict(),
            'message': '会话创建成功'
        }), 201
        
    except Exception as e:
        logger.error(f"创建会话失败: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': '创建会话失败'
        }), 500

@api_bp.route('/api/session/<session_id>', methods=['GET'])
@cross_origin()
def get_session(session_id):
    """获取会话信息"""
    try:
        if not _require_api_auth():
            return jsonify({'success': False, 'message': '未授权'}), 401
        session = Session.query.get(session_id)
        if not session:
            return jsonify({
                'success': False,
                'message': '会话不存在'
            }), 404
        
        return jsonify({
            'success': True,
            'session': session.to_dict()
        })
        
    except Exception as e:
        logger.error(f"获取会话失败: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': '获取会话失败'
        }), 500

@api_bp.route('/api/sessions', methods=['GET'])
@cross_origin()
def list_sessions():
    """获取所有会话列表"""
    try:
        if not _require_api_auth():
            return jsonify({'success': False, 'message': '未授权'}), 401
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        sessions = Session.query.order_by(Session.last_activity.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'success': True,
            'sessions': [session.to_dict() for session in sessions.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': sessions.total,
                'pages': sessions.pages
            }
        })
        
    except Exception as e:
        logger.error(f"获取会话列表失败: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': '获取会话列表失败'
        }), 500

@api_bp.route('/api/subdomain/generate', methods=['POST'])
@cross_origin()
def generate_subdomain():
    """生成子域名用于测试"""
    try:
        if not _require_api_auth():
            return jsonify({'success': False, 'message': '未授权'}), 401
        data = request.get_json() or {}
        payload_type = data.get('type', 'test')
        session_id = data.get('session_id')
        length = data.get('length', 12)
        
        # 验证长度
        if length < Config.SUBDOMAIN_MIN_LENGTH or length > Config.SUBDOMAIN_MAX_LENGTH:
            return jsonify({
                'success': False,
                'message': f'子域名长度必须在 {Config.SUBDOMAIN_MIN_LENGTH}-{Config.SUBDOMAIN_MAX_LENGTH} 之间'
            }), 400
        
        # 生成子域名
        if session_id:
            subdomain = SubdomainGenerator.generate_payload_subdomain(payload_type, session_id)
        else:
            subdomain = SubdomainGenerator.generate_random_subdomain(length)
        
        full_domain = f"{subdomain}.{Config.DOMAIN}"
        
        try:
            # 记录到白名单
            g = GeneratedSubdomain(
                subdomain=subdomain,
                domain=Config.DOMAIN,
                full_domain=full_domain,
                session_id=session_id,
                payload_type=payload_type
            )
            db.session.add(g)
            db.session.commit()
        except Exception as e:
            try:
                db.session.rollback()
            except Exception:
                pass
            # 不影响返回
        return jsonify({
            'success': True,
            'subdomain': subdomain,
            'full_domain': full_domain,
            'domain': Config.DOMAIN,
            'session_id': session_id,
            'type': payload_type
        })
        
    except Exception as e:
        logger.error(f"生成子域名失败: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': '生成子域名失败'
        }), 500

@api_bp.route('/api/logs', methods=['GET'])
@cross_origin()
def get_logs():
    """获取DNS查询日志"""
    try:
        if not _require_api_auth():
            return jsonify({'success': False, 'message': '未授权'}), 401
        # 查询参数
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        session_id = request.args.get('session_id')
        subdomain = request.args.get('subdomain')
        client_ip = request.args.get('client_ip')
        hours = request.args.get('hours', type=int)  # 最近N小时的日志
        
        # 构建查询
        query = DNSLog.query
        
        if session_id:
            query = query.filter(DNSLog.session_id == session_id)
        
        if subdomain:
            # 大小写不敏感匹配
            query = query.filter(db.func.lower(DNSLog.subdomain).like(f"%{subdomain.lower()}%"))
        
        if client_ip:
            query = query.filter(DNSLog.client_ip == client_ip)
        
        if hours:
            since_time = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(DNSLog.timestamp >= since_time)
        
        # 排序和分页
        logs = query.order_by(DNSLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'success': True,
            'logs': [log.to_dict() for log in logs.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': logs.total,
                'pages': logs.pages
            }
        })
        
    except Exception as e:
        logger.error(f"获取日志失败: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': '获取日志失败'
        }), 500

def _require_api_auth():
    """允许两种方式之一：登录会话 或 Bearer Token"""
    auth = request.headers.get('Authorization', '')
    if current_user.is_authenticated:
        return True
    if auth.startswith('Bearer '):
        raw = auth.split(' ', 1)[1].strip()
        token_hash = APIToken.hash_token(raw)
        token = APIToken.query.filter_by(token_hash=token_hash, is_active=True).first()
        if token:
            # 过期检查
            if token.expires_at and datetime.utcnow() > token.expires_at:
                return False
            token.last_used_at = datetime.utcnow()
            db.session.commit()
            return True
    return False

@api_bp.route('/api/logs/<session_id>', methods=['GET'])
@cross_origin()
def get_session_logs(session_id):
    """获取特定会话的DNS日志"""
    try:
        if not _require_api_auth():
            return jsonify({'success': False, 'message': '未授权'}), 401
        # 验证会话是否存在
        session = Session.query.get(session_id)
        if not session:
            return jsonify({
                'success': False,
                'message': '会话不存在'
            }), 404
        
        # 获取该会话的所有日志
        logs = DNSLog.query.filter(DNSLog.session_id == session_id)\
                          .order_by(DNSLog.timestamp.desc())\
                          .all()
        
        return jsonify({
            'success': True,
            'session': session.to_dict(),
            'logs': [log.to_dict() for log in logs],
            'count': len(logs)
        })
        
    except Exception as e:
        logger.error(f"获取会话日志失败: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': '获取会话日志失败'
        }), 500

@api_bp.route('/api/logs/check/<subdomain>', methods=['GET'])
@cross_origin()
def check_subdomain_logs(subdomain):
    """检查特定子域名的DNS查询记录"""
    try:
        if not _require_api_auth():
            return jsonify({'success': False, 'message': '未授权'}), 401
        # 获取该子域名的所有日志
        logs = DNSLog.query.filter(db.func.lower(DNSLog.subdomain) == subdomain.lower())\
                          .order_by(DNSLog.timestamp.desc())\
                          .all()
        
        return jsonify({
            'success': True,
            'subdomain': subdomain,
            'domain': Config.DOMAIN,
            'full_domain': f"{subdomain}.{Config.DOMAIN}",
            'logs': [log.to_dict() for log in logs],
            'count': len(logs),
            'has_logs': len(logs) > 0
        })
        
    except Exception as e:
        logger.error(f"检查子域名日志失败: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': '检查子域名日志失败'
        }), 500

@api_bp.route('/api/logs/export', methods=['GET'])
@cross_origin()
def export_logs():
    """导出日志为CSV"""
    try:
        import csv
        from io import StringIO
        # 复用查询参数
        session_id = request.args.get('session_id')
        subdomain = request.args.get('subdomain')
        client_ip = request.args.get('client_ip')
        hours = request.args.get('hours', type=int)

        query = DNSLog.query
        if session_id:
            query = query.filter(DNSLog.session_id == session_id)
        if subdomain:
            query = query.filter(db.func.lower(DNSLog.subdomain).like(f"%{subdomain.lower()}%"))
        if client_ip:
            query = query.filter(DNSLog.client_ip == client_ip)
        if hours:
            since_time = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(DNSLog.timestamp >= since_time)

        rows = query.order_by(DNSLog.timestamp.desc()).all()

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['id','timestamp','full_domain','subdomain','domain','client_ip','query_type','session_id'])
        for r in rows:
            d = r.to_dict()
            writer.writerow([
                d['id'], d['timestamp'], d['full_domain'], d['subdomain'], d['domain'],
                d['client_ip'], d['query_type'], d['session_id'] or ''
            ])
        csv_data = output.getvalue()
        return Response(
            csv_data,
            mimetype='text/csv; charset=utf-8',
            headers={'Content-Disposition': 'attachment; filename="dns_logs.csv"'}
        )
    except Exception as e:
        logger.error(f"导出日志失败: {e}")
        return jsonify({'success': False, 'message': '导出日志失败'}), 500

@api_bp.route('/api/logs/item/<int:log_id>', methods=['GET'])
@cross_origin()
def get_log_item(log_id: int):
    try:
        if not _require_api_auth():
            return jsonify({'success': False, 'message': '未授权'}), 401
        item = DNSLog.query.get(log_id)
        if not item:
            return jsonify({'success': False, 'message': '未找到'}), 404
        return jsonify({'success': True, 'log': item.to_dict()})
    except Exception as e:
        logger.error(f"获取日志详情失败: {e}")
        return jsonify({'success': False, 'message': '获取详情失败'}), 500

@api_bp.route('/api/logs/clear', methods=['DELETE'])
@cross_origin()
def clear_logs():
    """清空DNS日志"""
    try:
        if not _require_api_auth():
            return jsonify({'success': False, 'message': '未授权'}), 401
        session_id = request.args.get('session_id')
        hours = request.args.get('hours', type=int)
        
        query = DNSLog.query
        
        if session_id:
            query = query.filter(DNSLog.session_id == session_id)
        elif hours:
            since_time = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(DNSLog.timestamp < since_time)
        
        count = query.count()
        query.delete()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'已清除 {count} 条日志记录'
        })
        
    except Exception as e:
        logger.error(f"清除日志失败: {e}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e),
            'message': '清除日志失败'
        }), 500

@api_bp.route('/api/stats', methods=['GET'])
@cross_origin()
def get_stats():
    """获取统计信息"""
    try:
        # 简单缓存 30s，减少DB压力
        global _STATS_CACHE
        now = datetime.utcnow()
        if '_STATS_CACHE' in globals():
            cache = globals().get('_STATS_CACHE')
        else:
            cache = None
        if cache and cache.get('data') is not None and cache.get('ts') and (now - cache['ts']).total_seconds() < 30:
            return jsonify(cache['data'])
        # 统计可匿名访问保留（便于前端展示），如需加密可启用鉴权
        # 总日志数
        total_logs = DNSLog.query.count()
        
        # 今日日志数
        today = datetime.utcnow().date()
        today_logs = DNSLog.query.filter(
            db.func.date(DNSLog.timestamp) == today
        ).count()
        
        # 最近24小时日志数
        last_24h = datetime.utcnow() - timedelta(hours=24)
        recent_logs = DNSLog.query.filter(
            DNSLog.timestamp >= last_24h
        ).count()
        
        # 活跃会话数
        active_sessions = Session.query.filter(
            Session.last_activity >= last_24h
        ).count()
        
        # 唯一IP数（最近24小时）
        unique_ips = db.session.query(DNSLog.client_ip).filter(
            DNSLog.timestamp >= last_24h
        ).distinct().count()
        
        payload = {
            'success': True,
            'stats': {
                'total_logs': total_logs,
                'today_logs': today_logs,
                'recent_logs_24h': recent_logs,
                'active_sessions': active_sessions,
                'unique_ips_24h': unique_ips,
                'domain': Config.DOMAIN,
                'dns_host': Config.DNS_SERVER_HOST,
                'dns_port': Config.DNS_SERVER_PORT
            }
        }
        globals()['_STATS_CACHE'] = { 'data': payload, 'ts': now }
        return jsonify(payload)
        
    except Exception as e:
        logger.error(f"获取统计信息失败: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': '获取统计信息失败'
        }), 500

# ==================== Web界面路由 ====================

@web_bp.route('/')
@login_required
def index():
    """主页"""
    return render_template('index.html')

@web_bp.route('/logs')
@login_required
def logs_page():
    """日志页面"""
    return render_template('logs.html')

@web_bp.route('/sessions')
@login_required
def sessions_page():
    """会话管理页面"""
    return render_template('sessions.html')

@web_bp.route('/api')
@login_required
def api_docs():
    """API文档页面"""
    return render_template('api_docs.html')

@web_bp.route('/settings')
@login_required
def settings_page():
    """系统设置页面"""
    if (not current_user.is_authenticated) or (not getattr(current_user, 'is_admin', False)):
        abort(403)
    return render_template('settings.html')

# ==================== 系统设置（实例覆盖） ====================

@api_bp.route('/api/settings', methods=['GET'])
@cross_origin()
@login_required
def get_settings():
    try:
        # 仅管理员
        if (not current_user.is_authenticated) or (not getattr(current_user, 'is_admin', False)):
            return jsonify({'success': False, 'message': '需要管理员权限'}), 403
        data = {
            'DOMAIN': Config.DOMAIN,
            'NS1_DOMAIN': Config.NS1_DOMAIN,
            'NS2_DOMAIN': Config.NS2_DOMAIN,
            'NS_IP': Config.NS_IP,
            'A_RECORD_IP': Config.A_RECORD_IP,
            'DNS_SERVER_HOST': Config.DNS_SERVER_HOST,
            'DNS_SERVER_PORT': Config.DNS_SERVER_PORT,
            'WEB_SERVER_HOST': Config.WEB_SERVER_HOST,
            'WEB_SERVER_PORT': Config.WEB_SERVER_PORT,
            'SQLALCHEMY_DATABASE_URI': Config.SQLALCHEMY_DATABASE_URI,
            'LOG_RETENTION_DAYS': Config.LOG_RETENTION_DAYS,
        }
        return jsonify({'success': True, 'settings': data})
    except Exception as e:
        logger.error(f"读取设置失败: {e}")
        return jsonify({'success': False, 'message': '读取设置失败'}), 500

@api_bp.route('/api/settings', methods=['POST'])
@cross_origin()
@login_required
def update_settings():
    try:
        if (not current_user.is_authenticated) or (not getattr(current_user, 'is_admin', False)):
            return jsonify({'success': False, 'message': '需要管理员权限'}), 403
        payload = request.get_json() or {}
        # server-side validation
        import re
        def is_ip(v):
            return bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', v or ''))
        def is_hostname(v):
            return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', v or ''))
        def is_port(v):
            try:
                x = int(v)
                return 0 < x < 65536
            except Exception:
                return False
        errors = []
        if 'DOMAIN' in payload and payload['DOMAIN'] and not is_hostname(payload['DOMAIN']): errors.append('主域名格式不正确')
        if 'NS1_DOMAIN' in payload and payload['NS1_DOMAIN'] and not is_hostname(payload['NS1_DOMAIN']): errors.append('主 NS 域名格式不正确')
        if 'NS2_DOMAIN' in payload and payload['NS2_DOMAIN'] and not is_hostname(payload['NS2_DOMAIN']): errors.append('备 NS 域名格式不正确')
        if 'NS_IP' in payload and payload['NS_IP'] and not is_ip(payload['NS_IP']): errors.append('NS 服务器 IP 格式不正确')
        if 'A_RECORD_IP' in payload and payload['A_RECORD_IP'] and not is_ip(payload['A_RECORD_IP']): errors.append('A 记录 IP 格式不正确')
        if 'DNS_SERVER_PORT' in payload and payload['DNS_SERVER_PORT'] and not is_port(payload['DNS_SERVER_PORT']): errors.append('DNS 端口无效')
        if 'WEB_SERVER_PORT' in payload and payload['WEB_SERVER_PORT'] and not is_port(payload['WEB_SERVER_PORT']): errors.append('Web 端口无效')
        if 'LOG_RETENTION_DAYS' in payload and payload['LOG_RETENTION_DAYS']:
            try:
                v = int(payload['LOG_RETENTION_DAYS'])
                if v < 1 or v > 3650: errors.append('日志保留天数需在 1-3650')
            except Exception:
                errors.append('日志保留天数需为整数')
        if errors:
            return jsonify({'success': False, 'message': '；'.join(errors)}), 400
        allowed = ['DOMAIN','NS1_DOMAIN','NS2_DOMAIN','NS_IP','A_RECORD_IP','DNS_SERVER_HOST','DNS_SERVER_PORT','WEB_SERVER_HOST','WEB_SERVER_PORT','SQLALCHEMY_DATABASE_URI','LOG_RETENTION_DAYS']
        data = {k: payload.get(k) for k in allowed if k in payload}
        # 保存到 Flask 的 instance 目录，确保与加载时一致
        instance_dir = current_app.instance_path
        os.makedirs(instance_dir, exist_ok=True)
        cfg_file = os.path.join(instance_dir, 'config.json')
        existing = {}
        if os.path.exists(cfg_file):
            try:
                with open(cfg_file, 'r', encoding='utf-8') as f:
                    existing = json.load(f) or {}
            except Exception:
                existing = {}
        existing.update(data)
        with open(cfg_file, 'w', encoding='utf-8') as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)

        # 应用到运行时配置（内存）
        changed_keys = set(data.keys())
        def _cast_value(k, v):
            if k in ('DNS_SERVER_PORT','WEB_SERVER_PORT','LOG_RETENTION_DAYS'):
                try:
                    return int(v)
                except Exception:
                    return v
            return v
        try:
            for k, v in data.items():
                val = _cast_value(k, v)
                setattr(Config, k, val)
                current_app.config[k] = getattr(Config, k)
        except Exception:
            pass

        # 动态更新 DNS 解析器与服务器
        try:
            srv = getattr(current_app, 'dns_server', None)
            if srv:
                # 更新解析器关键字段
                if changed_keys & {'DOMAIN','NS1_DOMAIN','NS2_DOMAIN','NS_IP','A_RECORD_IP'}:
                    try:
                        srv.resolver.domain = Config.DOMAIN
                        srv.resolver.ns_ip = Config.NS_IP
                        srv.resolver.a_record_ip = Config.A_RECORD_IP
                    except Exception:
                        pass
                # 若监听地址/端口变化，则重启DNS服务
                if changed_keys & {'DNS_SERVER_HOST','DNS_SERVER_PORT'}:
                    try:
                        srv.stop()
                    except Exception:
                        pass
                    from app.dns_server import DNSLogServer
                    new_srv = DNSLogServer(current_app)
                    current_app.dns_server = new_srv
                    new_srv.start_threaded()
        except Exception:
            pass

        msg = '保存成功，已应用配置。若修改了 Web 监听，请重启 Web 服务生效'
        return jsonify({'success': True, 'message': msg})
    except Exception as e:
        logger.error(f"保存设置失败: {e}")
        return jsonify({'success': False, 'message': '保存失败'}), 500
