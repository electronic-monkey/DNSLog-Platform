#!/usr/bin/env python3
"""
DNSLog平台启动脚本
提供DNS日志记录服务和Web界面
"""

import os
import sys
import signal
import threading
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

def print_banner():
    """打印启动横幅"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                        DNSLog Platform                      ║
║                     DNS日志记录平台                          ║
╠══════════════════════════════════════════════════════════════╣
║  Author: SSRF Detection Tool                                ║
║  Domain: {domain:<50} ║
║  DNS Server: {dns_host}:{dns_port:<40} ║
║  Web Server: {web_host}:{web_port:<40} ║
╚══════════════════════════════════════════════════════════════╝
    """.format(
        domain=Config.DOMAIN,
        dns_host=Config.DNS_SERVER_HOST,
        dns_port=Config.DNS_SERVER_PORT,
        web_host=Config.WEB_SERVER_HOST,
        web_port=Config.WEB_SERVER_PORT
    )
    print(banner)

def main():
    """主函数"""
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 打印横幅
    print_banner()
    
    try:
        # 创建Flask应用
        logger.info("正在初始化Flask应用...")
        app = create_app()
        
        # 启动DNS服务器（在后台线程）
        logger.info("正在启动DNS服务器...")
        dns_thread = app.dns_server.start_threaded()
        
        # 等待一秒确保DNS服务器启动
        time.sleep(1)
        
        logger.info("=== 服务启动成功 ===")
        logger.info(f"DNS服务器: {Config.DNS_SERVER_HOST}:{Config.DNS_SERVER_PORT}")
        logger.info(f"Web界面: http://{Config.WEB_SERVER_HOST}:{Config.WEB_SERVER_PORT}")
        logger.info(f"API文档: http://{Config.WEB_SERVER_HOST}:{Config.WEB_SERVER_PORT}/api")
        logger.info(f"域名: {Config.DOMAIN}")
        logger.info("按 Ctrl+C 停止服务")
        
        # 启动Web服务器
        app.run(
            host=Config.WEB_SERVER_HOST,
            port=Config.WEB_SERVER_PORT,
            debug=False,
            threaded=True
        )
        
    except PermissionError as e:
        logger.error(f"权限错误: {e}")
        logger.error("DNS服务器需要root权限才能绑定到53端口")
        logger.error("请使用 sudo 运行此程序，或修改配置使用其他端口")
        sys.exit(1)
        
    except OSError as e:
        if e.errno == 98:  # Address already in use
            logger.error("端口已被占用，请检查是否有其他DNS服务正在运行")
            logger.error("或者修改配置文件中的端口设置")
        else:
            logger.error(f"系统错误: {e}")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"启动失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
