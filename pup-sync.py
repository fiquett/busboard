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

STATE_FILE = os.environ.get('PUP_STATE_FILE', os.path.join(os.path.dirname(__file__), 'pup-state.json'))
TOKEN = os.environ.get('PUP_SYNC_TOKEN', '')
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
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    def _authorized(self):
        if not TOKEN:
            return True
        auth = self.headers.get('Authorization', '')
        return auth == f'Bearer {TOKEN}'

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path == '/pups':
            if not self._authorized():
                self.send_response(401); self.end_headers(); return
            body = json.dumps(state).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self._cors()
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith('/gcal'):
            self._handle_gcal()
        else:
            self.send_response(404); self.end_headers()

    def _handle_gcal(self):
        import urllib.request as _req
        from urllib.parse import urlparse, parse_qs, urlencode, quote
        gcal_key = os.environ.get('GCAL_API_KEY', '')
        gcal_id  = os.environ.get('GCAL_CALENDAR_ID', '')
        if not gcal_key or not gcal_id:
            self.send_response(503)
            self._cors()
            self.end_headers()
            self.wfile.write(b'{"error":"Calendar not configured"}')
            return
        parsed = urlparse(self.path)
        params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        params['key'] = gcal_key
        url = (f'https://www.googleapis.com/calendar/v3/calendars/'
               f'{quote(gcal_id, safe="")}/events?{urlencode(params)}')
        try:
            with _req.urlopen(url, timeout=10) as r:
                body = r.read()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self._cors()
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            self.send_response(502)
            self._cors()
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())

    def do_POST(self):
        if self.path != '/pups':
            self.send_response(404); self.end_headers(); return
        if not self._authorized():
            self.send_response(401); self.end_headers(); return
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length))
        with lock:
            # Merge current state: latest *write time* (_w keys) wins.
            # Falls back to largest-value for keys without a write time.
            write_keys = {k for k in body if k.endswith('_w')}
            for k, v in body.items():
                if k in ('history', 'deleted_ids') or k.endswith('_w'):
                    continue
                wk = k + '_w'
                if wk in write_keys:
                    # Use write-time semantics: newer write wins
                    new_w = int(body.get(wk) or 0)
                    cur_w = int(state.get(wk) or 0)
                    if new_w > cur_w:
                        state[k]  = v
                        state[wk] = new_w
                else:
                    # Fallback: largest value wins (backward compat)
                    if int(v or 0) > int(state.get(k) or 0):
                        state[k] = v
            # merge deleted_ids: union (events marked deleted propagate to all clients)
            deleted = set(state.get('deleted_ids', []))
            deleted.update(body.get('deleted_ids', []))
            state['deleted_ids'] = list(deleted)
            # merge history: union by event id, excluding deleted, keep newest 1000
            remote_history = body.get('history', [])
            local_history = state.get('history', [])
            ids_seen = {e['id'] for e in local_history if e.get('id')}
            for event in remote_history:
                if event.get('id') and event['id'] not in ids_seen:
                    local_history.append(event)
                    ids_seen.add(event['id'])
            local_history = [e for e in local_history if e.get('id') not in deleted]
            local_history.sort(key=lambda e: e.get('ts', 0))
            state['history'] = local_history[-1000:]
            save()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self._cors()
        self.end_headers()
        self.wfile.write(json.dumps(state).encode())

HTTPServer(('0.0.0.0', 8765), Handler).serve_forever()
