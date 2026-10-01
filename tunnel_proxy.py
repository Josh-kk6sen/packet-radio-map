#!/usr/bin/env python3
import http.server
import urllib.request
import urllib.parse
import os
import mimetypes

ALLOWED = {"/map.html", "/api/heard-stations", "/api/map-markers", "/api/markers", "/api/stats", "/api/mapmsg", "/api/packets", "/favicon.ico"}
MAP_PATHS = {"/", "/map.html"}
BACKEND = "http://127.0.0.1:8080"
DOWNLOADS_DIR = os.environ.get("DOWNLOADS_DIR", "/var/www/html/downloads")

class NoErrorProcessor(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response
    def https_response(self, request, response):
        return response

opener = urllib.request.build_opener(NoErrorProcessor)

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        clean_path = urllib.parse.urlparse(self.path).path
        backend_path = self.path

        # Route /downloads/ to serve files directly
        if clean_path == "/downloads":
            self.send_response(301)
            self.send_header("Location", "/downloads/")
            self.end_headers()
            return
        if clean_path.startswith("/downloads/"):
            filename = clean_path[len("/downloads/"):]
            filepath = os.path.join(DOWNLOADS_DIR, filename)
            # Prevent directory traversal
            realpath = os.path.realpath(filepath)
            if not realpath.startswith(os.path.realpath(DOWNLOADS_DIR)):
                self.send_error(403, "Forbidden")
                return
            if not os.path.isfile(realpath):
                # Serve index.html for /downloads/ itself
                if filename == "" or filename == "index.html":
                    idx = os.path.join(DOWNLOADS_DIR, "index.html")
                    if os.path.isfile(idx):
                        realpath = idx
                    else:
                        self.send_error(404, "Not Found")
                        return
                else:
                    self.send_error(404, "Not Found")
                    return
            try:
                with open(realpath, "rb") as f:
                    body = f.read()
                content_type, _ = mimetypes.guess_type(realpath)
                self.send_response(200)
                self.send_header("Content-Type", content_type or "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                self.send_error(500, f"Error: {e}")
            return

        # Normal paths - proxy to map backend
        target = BACKEND
        if clean_path in MAP_PATHS:
            backend_path = "/map.html"
        allowed_path = urllib.parse.urlparse(backend_path).path
        if allowed_path not in ALLOWED:
            self.send_error(403, "Forbidden")
            return

        try:
            resp = opener.open(target + backend_path, timeout=5)
            body = resp.read()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_error(502, f"Backend error: {e}")

    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    http.server.HTTPServer(("127.0.0.1", 9090), ProxyHandler).serve_forever()
