from app import create_app

app = create_app()

if __name__ == '__main__':
    from app.config import Config
    app.run(host=Config.WEB_SERVER_HOST, port=Config.WEB_SERVER_PORT, debug=False, threaded=True)

