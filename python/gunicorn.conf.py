import multiprocessing, os

bind = os.getenv("WEB_BIND", "0.0.0.0:8000")
workers = int(os.getenv("WEB_WORKERS", str(max(2, multiprocessing.cpu_count() * 2 + 1))))
threads = int(os.getenv("WEB_THREADS", "2"))
worker_class = os.getenv("WEB_WORKER_CLASS", "gthread")
timeout = int(os.getenv("WEB_TIMEOUT", "60"))
keepalive = int(os.getenv("WEB_KEEPALIVE", "2"))
max_requests = int(os.getenv("WEB_MAX_REQUESTS", "1000"))
max_requests_jitter = int(os.getenv("WEB_MAX_REQUESTS_JITTER", "100"))
preload_app = True
accesslog = os.getenv("WEB_ACCESSLOG", "-")
errorlog = os.getenv("WEB_ERRORLOG", "-")
