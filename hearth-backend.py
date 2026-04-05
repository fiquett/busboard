#!/usr/bin/env python3
"""
hearth-backend.py — Unified backend for hearth.fiquett.com
Handles: pup sync, gcal proxy, Google OAuth, device activation, JWT sessions

Replaces pup-sync.py. Run with:
  pip install flask PyJWT requests && python3 hearth-backend.py
"""
import json, os, sqlite3, secrets, time, threading, base64
import urllib.request, urllib.parse
from flask import Flask, request, jsonify, redirect
from functools import wraps

try:
    import jwt as pyjwt
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'PyJWT', '-q'])
    import jwt as pyjwt

# ── Config ─────────────────────────────────────────────────────────────────────
DB_PATH              = os.environ.get('HEARTH_DB',            '/pup-data/hearth.db')
STATE_FILE           = os.environ.get('PUP_STATE_FILE',       '/pup-data/pup-state.json')
GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID',     '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
JWT_SECRET           = os.environ.get('HEARTH_JWT_SECRET',    '')
BASE_URL             = os.environ.get('HEARTH_BASE_URL',      'https://hearth.fiquett.com')
GCAL_API_KEY         = os.environ.get('GCAL_API_KEY',         '')
GCAL_CALENDAR_ID     = os.environ.get('GCAL_CALENDAR_ID',     '')
PORT                 = int(os.environ.get('PORT',              '8765'))

# Comma-separated list of allowed Google email addresses.
# Empty = open to any Google account (not recommended).
_ALLOWED_RAW = os.environ.get('HEARTH_ALLOWED_EMAILS', '')
ALLOWED_EMAILS: set[str] = (
    {e.strip().lower() for e in _ALLOWED_RAW.split(',') if e.strip()}
    if _ALLOWED_RAW else set()
)

SESSION_DAYS    = 180
INVITE_MINUTES  = 10

if not JWT_SECRET:
    raise RuntimeError(
        "HEARTH_JWT_SECRET env var not set. "
        "Generate: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
    )

app = Flask(__name__)

# ── CORS ───────────────────────────────────────────────────────────────────────
@app.after_request
def add_cors(resp):
    resp.headers['Access-Control-Allow-Origin']  = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return resp

@app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options(_path=''):
    return '', 204

# ── Database ───────────────────────────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS accounts (
            id          TEXT PRIMARY KEY,
            email       TEXT UNIQUE,
            google_sub  TEXT UNIQUE,
            name        TEXT,
            picture     TEXT,
            role        TEXT DEFAULT 'user',
            created_at  INTEGER
        );
        CREATE TABLE IF NOT EXISTS devices (
            id          TEXT PRIMARY KEY,
            account_id  TEXT,
            label       TEXT DEFAULT 'New Device',
            device_type TEXT DEFAULT 'unknown',
            settings    TEXT DEFAULT '{}',
            created_at  INTEGER,
            expires_at  INTEGER,
            revoked     INTEGER DEFAULT 0,
            last_seen   INTEGER
        );
        CREATE TABLE IF NOT EXISTS activation_codes (
            code        TEXT PRIMARY KEY,
            device_id   TEXT NOT NULL,
            created_at  INTEGER,
            expires_at  INTEGER,
            used        INTEGER DEFAULT 0
        );
    ''')
    db.commit()
    db.close()

# ── JWT helpers ────────────────────────────────────────────────────────────────
def issue_jwt(device_id, account_id, role, settings, days=SESSION_DAYS):
    now = int(time.time())
    return pyjwt.encode({
        'sub':        device_id,
        'account_id': account_id,
        'role':       role,
        'settings':   settings,
        'iat':        now,
        'exp':        now + days * 86400,
    }, JWT_SECRET, algorithm='HS256')

def verify_jwt(token):
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except Exception:
        return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        raw = request.headers.get('Authorization', '')
        token = raw[7:] if raw.startswith('Bearer ') else ''
        payload = verify_jwt(token) if token else None
        if not payload:
            return jsonify({'error': 'Unauthorized'}), 401
        db = get_db()
        row = db.execute('SELECT revoked FROM devices WHERE id=?',
                         (payload['sub'],)).fetchone()
        db.close()
        if not row or row['revoked']:
            return jsonify({'error': 'Token revoked'}), 401
        request.jwt = payload
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'jwt') or request.jwt.get('role') != 'admin':
            return jsonify({'error': 'Admin only'}), 403
        return f(*args, **kwargs)
    return decorated

# ── Pup sync (ported from pup-sync.py — same merge logic) ─────────────────────
pup_state = {}
pup_lock  = threading.Lock()

def load_pup_state():
    global pup_state
    try:
        with open(STATE_FILE) as f:
            pup_state = json.load(f)
    except Exception:
        pup_state = {}

def save_pup_state():
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(pup_state, f)
    except Exception:
        pass

@app.route('/pups', methods=['GET', 'POST'])
def pups():
    with pup_lock:
        if request.method == 'GET':
            return jsonify(pup_state)
        body = request.json or {}
        write_keys = {k for k in body if k.endswith('_w')}
        for k, v in body.items():
            if k in ('history', 'deleted_ids') or k.endswith('_w'):
                continue
            wk = k + '_w'
            if wk in write_keys:
                new_w = int(body.get(wk) or 0)
                cur_w = int(pup_state.get(wk) or 0)
                if new_w > cur_w:
                    pup_state[k]  = v
                    pup_state[wk] = new_w
            else:
                if int(v or 0) > int(pup_state.get(k) or 0):
                    pup_state[k] = v
        deleted = set(pup_state.get('deleted_ids', []))
        deleted.update(body.get('deleted_ids', []))
        pup_state['deleted_ids'] = list(deleted)
        remote_h = body.get('history', [])
        local_h  = pup_state.get('history', [])
        seen     = {e['id'] for e in local_h if e.get('id')}
        for ev in remote_h:
            if ev.get('id') and ev['id'] not in seen:
                local_h.append(ev)
                seen.add(ev['id'])
        local_h = [e for e in local_h if e.get('id') not in deleted]
        local_h.sort(key=lambda e: e.get('ts', 0))
        pup_state['history'] = local_h[-1000:]
        save_pup_state()
    return jsonify(pup_state)

# ── GCal proxy ─────────────────────────────────────────────────────────────────
@app.route('/gcal')
def gcal():
    if not GCAL_API_KEY or not GCAL_CALENDAR_ID:
        return jsonify({'error': 'Calendar not configured'}), 503
    params = dict(request.args)
    params['key'] = GCAL_API_KEY
    url = (f'https://www.googleapis.com/calendar/v3/calendars/'
           f'{urllib.parse.quote(GCAL_CALENDAR_ID, safe="")}/events?'
           f'{urllib.parse.urlencode(params)}')
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return app.response_class(r.read(), content_type='application/json')
    except Exception as e:
        return jsonify({'error': str(e)}), 502

# ── Google OAuth ───────────────────────────────────────────────────────────────
# Simple in-memory state store (single instance, fine for personal use)
_oauth_states: dict[str, float] = {}

@app.route('/auth/google')
def google_auth():
    state = secrets.token_urlsafe(16)
    _oauth_states[state] = time.time() + 600  # 10-min expiry
    # Clean up old states
    expired = [k for k, v in _oauth_states.items() if v < time.time()]
    for k in expired:
        del _oauth_states[k]
    params = {
        'client_id':     GOOGLE_CLIENT_ID,
        'redirect_uri':  f'{BASE_URL}/auth/google/callback',
        'response_type': 'code',
        'scope':         'openid email profile',
        'state':         state,
    }
    return redirect('https://accounts.google.com/o/oauth2/v2/auth?' +
                    urllib.parse.urlencode(params))

@app.route('/auth/google/callback')
def google_callback():
    state = request.args.get('state', '')
    expiry = _oauth_states.pop(state, 0)
    if expiry < time.time():
        return 'Invalid or expired state', 400
    code = request.args.get('code')
    if not code:
        return 'Missing authorization code', 400

    # Exchange code for tokens
    post_data = urllib.parse.urlencode({
        'code':          code,
        'client_id':     GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri':  f'{BASE_URL}/auth/google/callback',
        'grant_type':    'authorization_code',
    }).encode()
    try:
        req = urllib.request.Request(
            'https://oauth2.googleapis.com/token',
            data=post_data, method='POST')
        with urllib.request.urlopen(req, timeout=10) as r:
            tokens = json.loads(r.read())
    except Exception as e:
        return f'Token exchange failed: {e}', 500

    # Decode Google ID token (trust HTTPS — no sig verify needed for personal use)
    id_token = tokens.get('id_token', '')
    try:
        part = id_token.split('.')[1]
        part += '=' * (-len(part) % 4)
        claims = json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return 'Invalid ID token', 400

    google_sub = claims['sub']
    email      = claims.get('email', '')
    name       = claims.get('name', email)
    picture    = claims.get('picture', '')

    if ALLOWED_EMAILS and email.lower() not in ALLOWED_EMAILS:
        return '''<!DOCTYPE html><html><head><title>Not allowed</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{background:#0a0c10;color:#94a3b8;font-family:system-ui;
display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center}
.card{background:#12161e;border:1px solid #1e2530;border-radius:20px;padding:40px 32px;max-width:320px}
h1{color:#f87171;font-size:20px;margin-bottom:12px}p{font-size:14px;margin-bottom:20px}
a{color:#f59e0b;text-decoration:none}</style></head>
<body><div class="card"><h1>Not allowed</h1>
<p>This Google account isn't on the hearth allowlist.</p>
<a href="/login.html">← back</a></div></body></html>''', 403

    db = get_db()
    row = db.execute('SELECT id, role FROM accounts WHERE google_sub=?',
                     (google_sub,)).fetchone()
    if row:
        account_id, role = row['id'], row['role']
        db.execute('UPDATE accounts SET name=?, picture=? WHERE id=?',
                   (name, picture, account_id))
    else:
        account_id = secrets.token_urlsafe(16)
        count = db.execute('SELECT COUNT(*) FROM accounts').fetchone()[0]
        role  = 'admin' if count == 0 else 'user'
        db.execute(
            'INSERT INTO accounts (id,email,google_sub,name,picture,role,created_at) '
            'VALUES (?,?,?,?,?,?,?)',
            (account_id, email, google_sub, name, picture, role, int(time.time())))

    # Create a phone device record for this browser
    device_id = secrets.token_urlsafe(16)
    now = int(time.time())
    settings = {'device_type': 'phone', 'rooms': ['all'],
                'permissions': ['read', 'pup:write']}
    db.execute(
        'INSERT INTO devices '
        '(id,account_id,label,device_type,settings,created_at,expires_at,revoked,last_seen) '
        'VALUES (?,?,?,?,?,?,?,?,?)',
        (device_id, account_id, f"{name}'s phone", 'phone',
         json.dumps(settings), now, now + SESSION_DAYS * 86400, 0, now))
    db.commit()
    db.close()

    token = issue_jwt(device_id, account_id, role, settings)
    user_json  = json.dumps({'name': name, 'email': email, 'picture': picture})

    # Deliver token via HTML page (avoids URL exposure in history/logs)
    return f'''<!DOCTYPE html>
<html><head><title>Signing in…</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{{background:#0a0c10;color:#94a3b8;font-family:system-ui;
       display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
  p{{font-size:16px}}
</style>
</head><body><p>Signing in…</p>
<script>
try{{localStorage.setItem('hearth_token',{json.dumps(token)});}}catch(e){{}}
try{{localStorage.setItem('hearth_user',{json.dumps(user_json)});}}catch(e){{}}
window.location.replace('/');
</script></body></html>'''

# ── Device registration ────────────────────────────────────────────────────────
@app.route('/api/device/register', methods=['POST'])
def device_register():
    """Kiosk calls this on first load to get an unactivated device token."""
    device_id = secrets.token_urlsafe(16)
    now = int(time.time())
    settings = {'device_type': 'kiosk', 'activated': False,
                'rooms': [], 'permissions': []}
    db = get_db()
    db.execute(
        'INSERT INTO devices '
        '(id,account_id,label,device_type,settings,created_at,expires_at,revoked,last_seen) '
        'VALUES (?,?,?,?,?,?,?,?,?)',
        (device_id, None, 'Unactivated Kiosk', 'kiosk',
         json.dumps(settings), now, now + SESSION_DAYS * 86400, 0, now))
    db.commit()
    db.close()
    token = issue_jwt(device_id, None, 'kiosk_pending', settings)
    return jsonify({'token': token, 'device_id': device_id})

# ── Activation code ────────────────────────────────────────────────────────────
@app.route('/api/invite', methods=['POST'])
@require_auth
def invite():
    """Kiosk calls this to get a short-lived activation code to display."""
    device_id = request.jwt['sub']
    raw  = secrets.token_hex(3).upper()
    code = raw[:3] + '-' + raw[3:]
    now  = int(time.time())
    db = get_db()
    db.execute('DELETE FROM activation_codes WHERE device_id=?', (device_id,))
    db.execute(
        'INSERT INTO activation_codes (code,device_id,created_at,expires_at,used) '
        'VALUES (?,?,?,?,?)',
        (code, device_id, now, now + INVITE_MINUTES * 60, 0))
    db.commit()
    db.close()
    return jsonify({'code': code, 'expires_in': INVITE_MINUTES * 60})

@app.route('/api/device', methods=['GET'])
@require_auth
def device_status():
    """Kiosk polls this. Returns new_token once activated."""
    device_id = request.jwt['sub']
    db = get_db()
    row = db.execute('SELECT * FROM devices WHERE id=?', (device_id,)).fetchone()
    db.execute('UPDATE devices SET last_seen=? WHERE id=?',
               (int(time.time()), device_id))
    db.commit()
    db.close()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    settings  = json.loads(row['settings'] or '{}')
    activated = row['account_id'] is not None
    resp = {
        'id': row['id'], 'label': row['label'],
        'activated': activated, 'settings': settings,
    }
    # Issue a new token if the device just got activated
    if activated and not request.jwt.get('settings', {}).get('activated'):
        resp['new_token'] = issue_jwt(
            row['id'], row['account_id'], 'device', settings)
    return jsonify(resp)

# ── Phone activates a kiosk ────────────────────────────────────────────────────
@app.route('/api/activate', methods=['POST'])
@require_auth
def activate():
    data      = request.json or {}
    code      = data.get('code', '').upper().replace(' ', '')
    label     = data.get('label', 'Kiosk Display')
    custom    = data.get('settings', {})
    account_id = request.jwt.get('account_id')

    if not account_id:
        return jsonify({'error': 'Must be logged in with a user account'}), 403

    db = get_db()
    inv = db.execute(
        'SELECT * FROM activation_codes WHERE code=? AND used=0 AND expires_at>?',
        (code, int(time.time()))).fetchone()
    if not inv:
        db.close()
        return jsonify({'error': 'Invalid or expired code'}), 400

    device_id = inv['device_id']
    settings = {
        'device_type': 'kiosk',
        'activated':   True,
        'rooms':       custom.get('rooms', ['all']),
        'permissions': custom.get('permissions', ['read', 'pup:write']),
        'layout':      custom.get('layout', 'kiosk'),
    }
    db.execute('UPDATE activation_codes SET used=1 WHERE code=?', (code,))
    db.execute(
        'UPDATE devices SET account_id=?,label=?,device_type=?,settings=? WHERE id=?',
        (account_id, label, 'kiosk', json.dumps(settings), device_id))
    db.commit()
    db.close()
    return jsonify({'ok': True, 'device_id': device_id})

# ── Admin ──────────────────────────────────────────────────────────────────────
@app.route('/api/devices')
@require_auth
@require_admin
def list_devices():
    db = get_db()
    rows = db.execute(
        'SELECT d.*, a.email, a.name AS account_name '
        'FROM devices d LEFT JOIN accounts a ON d.account_id=a.id '
        'ORDER BY d.created_at DESC').fetchall()
    db.close()
    return jsonify([{
        'id':            r['id'],
        'label':         r['label'],
        'device_type':   r['device_type'],
        'activated':     r['account_id'] is not None,
        'account_email': r['email'],
        'account_name':  r['account_name'],
        'revoked':       bool(r['revoked']),
        'created_at':    r['created_at'],
        'expires_at':    r['expires_at'],
        'last_seen':     r['last_seen'],
        'settings':      json.loads(r['settings'] or '{}'),
    } for r in rows])

@app.route('/api/devices/<device_id>', methods=['PATCH'])
@require_auth
@require_admin
def update_device(device_id):
    data = request.json or {}
    db = get_db()
    if 'label' in data:
        db.execute('UPDATE devices SET label=? WHERE id=?', (data['label'], device_id))
    if 'settings' in data:
        db.execute('UPDATE devices SET settings=? WHERE id=?',
                   (json.dumps(data['settings']), device_id))
    db.commit()
    db.close()
    return jsonify({'ok': True})

@app.route('/api/revoke/<device_id>', methods=['POST'])
@require_auth
@require_admin
def revoke(device_id):
    db = get_db()
    db.execute('UPDATE devices SET revoked=1 WHERE id=?', (device_id,))
    db.commit()
    db.close()
    return jsonify({'ok': True})

@app.route('/api/accounts')
@require_auth
@require_admin
def list_accounts():
    db = get_db()
    rows = db.execute(
        'SELECT id,email,name,picture,role,created_at FROM accounts').fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

# ── Startup ────────────────────────────────────────────────────────────────────
init_db()
load_pup_state()

if __name__ == '__main__':
    print(f'[hearth-backend] Starting on 127.0.0.1:{PORT}', flush=True)
    app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False)
