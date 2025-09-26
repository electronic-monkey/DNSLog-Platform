#!/usr/bin/env python3
"""
用户管理脚本
用于创建、删除和管理DNSLog平台用户
"""

import sys
import os

# 添加应用路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.models import db, User
import click

def get_app():
    """获取应用实例"""
    return create_app()

@click.group()
def cli():
    """DNSLog平台用户管理工具"""
    pass

@cli.command()
@click.option('--username', prompt='用户名', help='用户名')
@click.option('--password', prompt='密码', hide_input=True, confirmation_prompt=True, help='密码')
@click.option('--admin', is_flag=True, help='设置为管理员')
def create_user(username, password, admin):
    """创建新用户"""
    app = get_app()
    
    with app.app_context():
        # 检查用户是否已存在
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            click.echo(f'错误: 用户 {username} 已存在')
            return
        
        # 创建新用户
        user = User(
            username=username,
            is_admin=admin,
            is_active=True
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        role = '管理员' if admin else '普通用户'
        click.echo(f'成功创建用户: {username} ({role})')

@cli.command()
@click.option('--username', prompt='用户名', help='要删除的用户名')
@click.confirmation_option(prompt='确定要删除此用户吗？')
def delete_user(username):
    """删除用户"""
    app = get_app()
    
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f'错误: 用户 {username} 不存在')
            return
        
        db.session.delete(user)
        db.session.commit()
        
        click.echo(f'成功删除用户: {username}')

@cli.command()
def list_users():
    """列出所有用户"""
    app = get_app()
    
    with app.app_context():
        users = User.query.all()
        
        if not users:
            click.echo('没有找到用户')
            return
        
        click.echo('用户列表:')
        click.echo('=' * 60)
        click.echo(f'{"ID":<5} {"用户名":<15} {"角色":<10} {"状态":<8} {"创建时间":<20}')
        click.echo('-' * 60)
        
        for user in users:
            role = '管理员' if user.is_admin else '普通用户'
            status = '激活' if user.is_active else '停用'
            created = user.created_at.strftime('%Y-%m-%d %H:%M:%S')
            
            click.echo(f'{user.id:<5} {user.username:<15} {role:<10} {status:<8} {created:<20}')

@cli.command()
@click.option('--username', prompt='用户名', help='用户名')
@click.option('--password', prompt='新密码', hide_input=True, confirmation_prompt=True, help='新密码')
def change_password(username, password):
    """修改用户密码"""
    app = get_app()
    
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f'错误: 用户 {username} 不存在')
            return
        
        user.set_password(password)
        db.session.commit()
        
        click.echo(f'成功修改用户 {username} 的密码')

@cli.command()
@click.option('--username', prompt='用户名', help='用户名')
@click.option('--active/--inactive', default=True, help='激活或停用用户')
def toggle_user(username, active):
    """激活或停用用户"""
    app = get_app()
    
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f'错误: 用户 {username} 不存在')
            return
        
        user.is_active = active
        db.session.commit()
        
        status = '激活' if active else '停用'
        click.echo(f'成功{status}用户: {username}')

@cli.command()
@click.option('--username', prompt='用户名', help='用户名')
@click.option('--admin/--no-admin', default=None, help='设置或取消管理员权限')
def set_admin(username, admin):
    """设置或取消用户的管理员权限"""
    if admin is None:
        admin = click.confirm(f'设置用户 {username} 为管理员吗？')
    
    app = get_app()
    
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if not user:
            click.echo(f'错误: 用户 {username} 不存在')
            return
        
        user.is_admin = admin
        db.session.commit()
        
        role = '管理员' if admin else '普通用户'
        click.echo(f'成功设置用户 {username} 为{role}')

@cli.command()
def reset_admin():
    """重置默认管理员账户"""
    app = get_app()
    
    with app.app_context():
        # 查找现有的admin用户
        admin_user = User.query.filter_by(username='admin').first()
        
        if admin_user:
            # 重置密码
            admin_user.set_password('123456')
            admin_user.is_admin = True
            admin_user.is_active = True
            db.session.commit()
            click.echo('成功重置管理员账户密码为: 123456')
        else:
            # 创建新的管理员账户
            admin_user = User.create_admin_user()
            click.echo('成功创建默认管理员账户: admin / 123456')

if __name__ == '__main__':
    cli()
