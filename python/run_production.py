#!/usr/bin/env python3
"""
DNSLog平台生产模式启动脚本
使用gunicorn作为WSGI服务器，提供更好的性能和稳定性
"""

import os
import sys
import signal
import subprocess
import time
from app import create_app
from app.config import Config
import logging

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def signal_handler(signum, frame):
    """处理信号，优雅退出"""
    logger.info("收到退出信号，正在关闭服务...")
    sys.exit(0)

def print_production_banner():
    """打印生产模式横幅"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                DNSLog Platform (生产模式)                    ║
║                     DNS日志记录平台                          ║
╠══════════════════════════════════════════════════════════════╣
║  服务器: Gunicorn (生产级WSGI服务器)                         ║
║  DNS Server: {dns_host}:{dns_port:<40} ║
║  Web Server: {web_host}:{web_port:<40} ║
║  域名: {domain:<50} ║
║  进程数: 4 (自动根据CPU核心数调整)                           ║
╚══════════════════════════════════════════════════════════════╝
    """.format(
        domain=Config.DOMAIN,
        dns_host=Config.DNS_SERVER_HOST,
        dns_port=Config.DNS_SERVER_PORT,
        web_host=Config.WEB_SERVER_HOST,
        web_port=Config.WEB_SERVER_PORT
    )
    print(banner)

def check_gunicorn():
    """检查gunicorn是否已安装"""
    try:
        import gunicorn
        return True
    except ImportError:
        return False

def install_gunicorn():
    """安装gunicorn"""
    logger.info("正在安装gunicorn...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'gunicorn'])
        logger.info("✅ gunicorn安装成功")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ gunicorn安装失败: {e}")
        return False

def start_dns_server():
    """启动DNS服务器"""
    try:
        logger.info("正在启动DNS服务器...")
        app = create_app()
        dns_thread = app.dns_server.start_threaded()
        time.sleep(2)  # 等待DNS服务器启动
        logger.info("✅ DNS服务器启动成功")
        return dns_thread
    except Exception as e:
        logger.error(f"❌ DNS服务器启动失败: {e}")
        return None

def main():
    """主函数"""
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 打印横幅
    print_production_banner()
    
    # 检查是否为root权限
    if os.geteuid() != 0:
        logger.warning("⚠️  建议使用root权限运行以绑定DNS端口53")
    
    # 检查gunicorn
    if not check_gunicorn():
        logger.info("未找到gunicorn，正在安装...")
        if not install_gunicorn():
            logger.error("无法安装gunicorn，请手动安装: pip install gunicorn")
            sys.exit(1)
    
    try:
        # 启动DNS服务器
        dns_thread = start_dns_server()
        if not dns_thread:
            logger.error("DNS服务器启动失败，退出")
            sys.exit(1)
        
        # 配置gunicorn参数
        host = Config.WEB_SERVER_HOST
        port = Config.WEB_SERVER_PORT
        workers = os.cpu_count() or 4  # 根据CPU核心数设置工作进程
        
        # 构建gunicorn命令
        gunicorn_cmd = [
            'gunicorn',
            '--bind', f'{host}:{port}',
            '--workers', str(workers),
            '--worker-class', 'sync',
            '--timeout', '120',
            '--keepalive', '2',
            '--max-requests', '1000',
            '--max-requests-jitter', '100',
            '--preload',
            '--access-logfile', '-',
            '--error-logfile', '-',
            '--log-level', 'info',
            'app:create_app()'
        ]
        
        logger.info("=== 服务启动成功 ===")
        logger.info(f"DNS服务器: {Config.DNS_SERVER_HOST}:{Config.DNS_SERVER_PORT}")
        logger.info(f"Web服务器: http://{host}:{port}")
        logger.info(f"API文档: http://{host}:{port}/api")
        logger.info(f"域名: {Config.DOMAIN}")
        logger.info(f"工作进程数: {workers}")
        logger.info("按 Ctrl+C 停止服务")
        logger.info("")
        
        # 启动gunicorn
        logger.info("正在启动Gunicorn Web服务器...")
        subprocess.run(gunicorn_cmd)
        
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在关闭服务...")
    except FileNotFoundError:
        logger.error("❌ 未找到gunicorn命令，请确保已正确安装")
        logger.error("   尝试: pip install gunicorn")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ 启动失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
