#!/usr/bin/env python3
"""
Pup sync server — run on Pi 3 to share pup state across all hearth screens.
Usage: python3 ~/hearth/pup-sync.py
Then set PUP_SYNC_URL = 'http://10.0.0.6:8765' in hearth/index.html config.

State persists in pup-state.json next to this file.
Autostart: add to Pi 3 ~/.config/openbox/autostart:
  python3 ~/hearth/pup-sync.py &
"""
import json, os, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE_FILE = os.path.join(os.path.dirname(__file__), 'pup-state.json')
state = {}
lock = threading.Lock()

def load():
    global state
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
    except Exception:
        state = {}

def save():
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)

load()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # suppress request logs

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path != '/pups':
            self.send_response(404); self.end_headers(); return
        body = json.dumps(state).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != '/pups':
            self.send_response(404); self.end_headers(); return
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length))
        with lock:
            # merge: keep latest timestamp per key
            for k, v in body.items():
                if int(v or 0) > int(state.get(k) or 0):
                    state[k] = v
            save()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self._cors()
        self.end_headers()
        self.wfile.write(json.dumps(state).encode())

HTTPServer(('0.0.0.0', 8765), Handler).serve_forever()
