#!/usr/bin/env python3
"""
DNSLog平台开发模式启动脚本
使用非特权端口，无需root权限
"""

import os
import sys
import signal
import time
from app import create_app
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

def print_dev_banner():
    """打印开发模式横幅"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                   DNSLog Platform (开发模式)                 ║
║                     DNS日志记录平台                          ║
╠══════════════════════════════════════════════════════════════╣
║  模式: 开发模式（无需root权限）                               ║
║  DNS Server: 127.0.0.1:5353                                 ║
║  Web Server: 127.0.0.1:8000                                 ║
║  域名: cyj520.icu (来自配置)                                 ║
╠══════════════════════════════════════════════════════════════╣
║  注意: 开发模式下DNS服务器监听5353端口                        ║
║  要测试DNS功能，请使用:                                      ║
║  nslookup test.cyj520.icu 127.0.0.1 -port=5353              ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    """主函数"""
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 设置开发模式环境变量
    os.environ['DNS_SERVER_PORT'] = '5353'  # 非特权端口
    os.environ['DNS_SERVER_HOST'] = '127.0.0.1'
    os.environ['WEB_SERVER_HOST'] = '127.0.0.1'
    os.environ['WEB_SERVER_PORT'] = '8000'
    
    # 打印横幅
    print_dev_banner()
    
    try:
        # 创建Flask应用
        logger.info("正在初始化Flask应用...")
        app = create_app()
        
        # 启动DNS服务器（在后台线程）
        logger.info("正在启动DNS服务器（端口5353）...")
        dns_thread = app.dns_server.start_threaded()
        
        # 等待一秒确保DNS服务器启动
        time.sleep(1)
        
        logger.info("=== 开发环境启动成功 ===")
        logger.info("DNS服务器: 127.0.0.1:5353")
        logger.info("Web界面: http://127.0.0.1:8000")
        logger.info("API文档: http://127.0.0.1:8000/api")
        logger.info("")
        logger.info("测试DNS查询:")
        logger.info("  nslookup test.cyj520.icu 127.0.0.1 -port=5353")
        logger.info("  dig @127.0.0.1 -p 5353 test.cyj520.icu")
        logger.info("")
        logger.info("按 Ctrl+C 停止服务")
        
        # 启动Web服务器
        app.run(
            host='127.0.0.1',
            port=8000,
            debug=True,
            threaded=True
        )
        
    except Exception as e:
        logger.error(f"启动失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
