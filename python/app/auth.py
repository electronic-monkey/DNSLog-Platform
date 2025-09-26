from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.urls import url_parse
from app.models import db, User, APIToken, LoginSecurity
import secrets
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

# 创建认证蓝图
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """登录页面和处理"""
    # 如果已经登录，重定向到首页
    if current_user.is_authenticated:
        return redirect(url_for('web.index'))
    
    if request.method == 'POST':
        # 统一登录处理（表单/JSON 共用）
        if request.is_json:
            data = request.get_json() or {}
            username = data.get('username')
            password = data.get('password')
            remember_me = data.get('remember_me', False)
        else:
            username = request.form.get('username')
            password = request.form.get('password')
            remember_me = bool(request.form.get('remember_me'))
        
        if not username or not password:
            flash('请输入用户名和密码', 'error')
            return render_template('auth/login.html')
        
        user = User.query.filter_by(username=username).first()

        # 检查锁定
        if user:
            sec = user.login_security or LoginSecurity(user_id=user.id)
            if sec.locked_until and datetime.utcnow() < sec.locked_until:
                flash('账户已锁定，请稍后再试', 'error')
                return render_template('auth/login.html')

        if user and user.check_password(password) and user.is_active:
            # 更新最后登录时间
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # 重置失败计数
            try:
                sec = user.login_security or LoginSecurity(user_id=user.id)
                sec.failed_attempts = 0
                sec.locked_until = None
                db.session.add(sec)
                db.session.commit()
            except Exception:
                db.session.rollback()

            # 登录用户
            login_user(user, remember=remember_me)
            logger.info(f"用户 {username} 登录成功")
            
            # 重定向到原来要访问的页面或首页
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('web.index')
            
            if request.is_json:
                return jsonify({'success': True, 'message': '登录成功', 'redirect_url': next_page}), 200
            return redirect(next_page)
        else:
            # 增加失败计数并可能锁定
            if user:
                try:
                    sec = user.login_security or LoginSecurity(user_id=user.id)
                    sec.failed_attempts = (sec.failed_attempts or 0) + 1
                    sec.last_failed_at = datetime.utcnow()
                    if sec.failed_attempts >= 5:
                        from datetime import timedelta
                        sec.locked_until = datetime.utcnow() + timedelta(minutes=10)
                    db.session.add(sec)
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            logger.warning(f"用户 {username} 登录失败")
            if request.is_json:
                return jsonify({'success': False, 'message': '用户名或密码错误'}), 401
            flash('用户名或密码错误', 'error')
    
    return render_template('auth/login.html')

def handle_ajax_login():
    # 已由统一登录逻辑处理
    return jsonify({'success': False, 'message': '不支持的方法'}), 405

@auth_bp.route('/logout')
@login_required
def logout():
    """登出"""
    username = current_user.username
    logout_user()
    logger.info(f"用户 {username} 已登出")
    flash('已成功登出', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/profile')
@login_required
def profile():
    """用户资料页面"""
    return render_template('auth/profile.html', user=current_user)

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """修改密码"""
    try:
        if request.is_json:
            data = request.get_json()
            current_password = data.get('current_password')
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')
        else:
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
        
        # 验证当前密码
        if not current_user.check_password(current_password):
            return jsonify({
                'success': False,
                'message': '当前密码错误'
            }), 400
        
        # 验证新密码（复杂度：至少8位，含大小写、数字）
        import re
        if not new_password or len(new_password) < 8:
            return jsonify({
                'success': False,
                'message': '新密码至少需要8位字符'
            }), 400
        if not re.search(r'[A-Z]', new_password) or not re.search(r'[a-z]', new_password) or not re.search(r'\d', new_password):
            return jsonify({
                'success': False,
                'message': '新密码需包含大写字母、小写字母和数字'
            }), 400
        
        if new_password != confirm_password:
            return jsonify({
                'success': False,
                'message': '两次输入的密码不一致'
            }), 400
        
        # 更新密码
        current_user.set_password(new_password)
        db.session.commit()
        
        logger.info(f"用户 {current_user.username} 修改密码成功")
        
        return jsonify({
            'success': True,
            'message': '密码修改成功'
        })
        
    except Exception as e:
        logger.error(f"修改密码失败: {e}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': '修改密码失败'
        }), 500

@auth_bp.route('/api/current-user')
@login_required
def current_user_api():
    """获取当前用户信息API"""
    return jsonify({
        'success': True,
        'user': current_user.to_dict()
    })

@auth_bp.route('/api/check-auth')
def check_auth():
    """检查认证状态API"""
    return jsonify({
        'authenticated': current_user.is_authenticated,
        'user': current_user.to_dict() if current_user.is_authenticated else None
    })

@auth_bp.route('/tokens', methods=['GET'])
@login_required
def list_tokens_page():
    """API Token 管理页面"""
    return render_template('auth/tokens.html', tokens=current_user.api_tokens.order_by(APIToken.created_at.desc()).all())

@auth_bp.route('/api/tokens', methods=['GET'])
@login_required
def list_tokens():
    tokens = current_user.api_tokens.order_by(APIToken.created_at.desc()).all()
    return jsonify({'success': True, 'tokens': [t.to_dict() for t in tokens]})

@auth_bp.route('/api/tokens', methods=['POST'])
@login_required
def create_token():
    data = request.get_json() or {}
    name = data.get('name') or 'API Token'
    scope = data.get('scope') or 'api'
    ttl_days = data.get('ttl_days')
    raw_token = secrets.token_urlsafe(32)
    token_hash = APIToken.hash_token(raw_token)
    expires_at = None
    try:
        if ttl_days:
            ttl = int(ttl_days)
            if ttl > 0:
                expires_at = datetime.utcnow() + timedelta(days=ttl)
    except Exception:
        pass
    token = APIToken(user_id=current_user.id, name=name, token_hash=token_hash, scope=scope, expires_at=expires_at)
    db.session.add(token)
    db.session.commit()
    return jsonify({'success': True, 'token': token.to_dict(), 'raw_token': raw_token})

@auth_bp.route('/api/tokens/<int:token_id>', methods=['DELETE'])
@login_required
def delete_token(token_id: int):
    token = APIToken.query.filter_by(id=token_id, user_id=current_user.id).first()
    if not token:
        return jsonify({'success': False, 'message': 'Token不存在'}), 404
    db.session.delete(token)
    db.session.commit()
    return jsonify({'success': True, 'message': '已删除'})

@auth_bp.route('/api/tokens/<int:token_id>', methods=['PATCH'])
@login_required
def update_token(token_id: int):
    """更新Token属性：name/scope/is_active/ttl_days（重置或延长过期时间）。"""
    token = APIToken.query.filter_by(id=token_id, user_id=current_user.id).first()
    if not token:
        return jsonify({'success': False, 'message': 'Token不存在'}), 404
    data = request.get_json() or {}
    try:
        name = data.get('name', None)
        if name is not None:
            token.name = name[:120]
        scope = data.get('scope', None)
        if scope is not None:
            if scope in ('api','read','admin'):
                token.scope = scope
            else:
                return jsonify({'success': False, 'message': '无效的scope'}), 400
        if 'is_active' in data:
            token.is_active = bool(data.get('is_active'))
        if 'ttl_days' in data:
            ttl_days = data.get('ttl_days')
            if ttl_days in (None, '', 0, '0'):
                token.expires_at = None
            else:
                try:
                    ttl = int(ttl_days)
                    if ttl > 0:
                        token.expires_at = datetime.utcnow() + timedelta(days=ttl)
                except Exception:
                    return jsonify({'success': False, 'message': 'ttl_days 无效'}), 400
        db.session.add(token)
        db.session.commit()
        return jsonify({'success': True, 'token': token.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'更新失败: {e}'}), 500

# ==================== 用户管理（管理员） ====================

@auth_bp.route('/users', methods=['GET'])
@login_required
def users_page():
    if (not current_user.is_authenticated) or (not getattr(current_user, 'is_admin', False)):
        return redirect(url_for('web.index'))
    return render_template('auth/users.html')

@auth_bp.route('/api/users', methods=['GET'])
@login_required
def list_users_api():
    if (not current_user.is_authenticated) or (not getattr(current_user, 'is_admin', False)):
        return jsonify({'success': False, 'message': '需要管理员权限'}), 403
    users = User.query.order_by(User.id.asc()).all()
    return jsonify({'success': True, 'users': [u.to_dict() for u in users]})

@auth_bp.route('/api/users', methods=['POST'])
@login_required
def create_user_api():
    if (not current_user.is_authenticated) or (not getattr(current_user, 'is_admin', False)):
        return jsonify({'success': False, 'message': '需要管理员权限'}), 403
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    is_admin = bool(data.get('is_admin', False))
    if not username or not password:
        return jsonify({'success': False, 'message': '用户名与密码必填'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': '用户名已存在'}), 409
    try:
        u = User(username=username, is_admin=is_admin, is_active=True)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        return jsonify({'success': True, 'user': u.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'创建失败: {e}'}), 500

@auth_bp.route('/api/users/<int:user_id>', methods=['PATCH'])
@login_required
def update_user_api(user_id: int):
    if (not current_user.is_authenticated) or (not getattr(current_user, 'is_admin', False)):
        return jsonify({'success': False, 'message': '需要管理员权限'}), 403
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'}), 404
    data = request.get_json() or {}
    try:
        if 'is_active' in data:
            if user.id == current_user.id and not bool(data.get('is_active')):
                return jsonify({'success': False, 'message': '不能停用自身账户'}), 400
            user.is_active = bool(data.get('is_active'))
        if 'is_admin' in data:
            if user.id == current_user.id and not bool(data.get('is_admin')):
                return jsonify({'success': False, 'message': '不能取消自身管理员权限'}), 400
            user.is_admin = bool(data.get('is_admin'))
        if 'password' in data and (data.get('password') or '').strip():
            new_pw = (data.get('password') or '').strip()
            # 简单强度校验：至少8位且含大小写与数字
            import re
            if (len(new_pw) < 8) or (not re.search(r'[A-Z]', new_pw)) or (not re.search(r'[a-z]', new_pw)) or (not re.search(r'\d', new_pw)):
                return jsonify({'success': False, 'message': '新密码需至少8位且包含大小写字母与数字'}), 400
            user.set_password(new_pw)
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True, 'user': user.to_dict()})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'更新失败: {e}'}), 500

@auth_bp.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user_api(user_id: int):
    if (not current_user.is_authenticated) or (not getattr(current_user, 'is_admin', False)):
        return jsonify({'success': False, 'message': '需要管理员权限'}), 403
    if user_id == current_user.id:
        return jsonify({'success': False, 'message': '不能删除自身账户'}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'}), 404
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': '已删除'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'删除失败: {e}'}), 500
