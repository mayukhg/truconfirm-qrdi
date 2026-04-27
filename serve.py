"""
No-cache static file server for TruConfirm QRDI
Run: python serve.py
"""
import http.server, os

PORT = 8888
BASE = os.path.dirname(os.path.abspath(__file__))

class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE, **kwargs)

    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def log_message(self, fmt, *args):
        pass  # suppress access logs

if __name__ == '__main__':
    with http.server.HTTPServer(('', PORT), NoCacheHandler) as httpd:
        print(f"\n[OK] TruConfirm QRDI frontend - no-cache server")
        print(f"   App  ->  http://localhost:{PORT}\n")
        httpd.serve_forever()
