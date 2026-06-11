#!/usr/bin/env python3
"""Claude desktop app account capture / restore.

This manages the Claude macOS desktop app state, which is separate from
Claude Code's ~/.claude credentials. Bundles are stored under
~/.ccs/desktop-app/vault and contain real session cookies, so keep that
directory private.
"""

import base64
import datetime
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from hashlib import pbkdf2_hmac

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception as e:
    print(f'Error: Python package "cryptography" is required: {e}', file=sys.stderr)
    sys.exit(1)


HOME = os.path.expanduser('~')
SUPPORT = os.path.join(HOME, 'Library', 'Application Support', 'Claude')
CONFIG_JSON = os.path.join(SUPPORT, 'config.json')
COOKIES_DB = os.path.join(SUPPORT, 'Cookies')
CLAUDE_JSON = os.path.join(HOME, '.claude.json')

CCS_DESKTOP_DIR = os.path.join(HOME, '.ccs', 'desktop-app')
VAULT = os.path.join(CCS_DESKTOP_DIR, 'vault')
BACKUPS = os.path.join(CCS_DESKTOP_DIR, 'backups')
LOG_PATH = os.path.join(CCS_DESKTOP_DIR, 'desktop-app.log')

SAFE_STORAGE_SERVICE = 'Claude Safe Storage'
SAFE_STORAGE_ACCOUNT = 'Claude Key'

COOKIE_COLS = [
    'creation_utc', 'host_key', 'top_frame_site_key', 'name', 'value', 'encrypted_value',
    'path', 'expires_utc', 'is_secure', 'is_httponly', 'last_access_utc', 'has_expires',
    'is_persistent', 'priority', 'samesite', 'source_scheme', 'source_port', 'last_update_utc',
    'source_type', 'has_cross_site_ancestor',
]


def log(msg):
    ts = datetime.datetime.now().isoformat(timespec='seconds')
    line = f'[{ts}] [desktop-app] {msg}'
    print(line)
    try:
        os.makedirs(CCS_DESKTOP_DIR, exist_ok=True)
        with open(LOG_PATH, 'a', encoding='utf8') as f:
            f.write(line + '\n')
    except Exception:
        pass


def _safe(name):
    return re.sub(r'[^A-Za-z0-9.@_-]', '_', str(name or '').strip())


def _bundle_path(name):
    safe = _safe(name)
    if not safe:
        raise RuntimeError('name is required')
    return os.path.join(VAULT, f'{safe}.json')


def _read_json(path, default=None):
    try:
        with open(path, encoding='utf8') as f:
            return json.load(f)
    except Exception:
        return default


def _write_json(path, data, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    if mode is not None:
        os.chmod(path, mode)


def app_running():
    r = subprocess.run(['pgrep', '-x', 'Claude'], capture_output=True, text=True)
    return r.returncode == 0


def require_macos():
    if sys.platform != 'darwin':
        raise RuntimeError('Claude App account switching is only supported on macOS')


def require_app_files():
    missing = [p for p in (CONFIG_JSON, COOKIES_DB) if not os.path.exists(p)]
    if missing:
        raise RuntimeError('Claude App data not found: ' + ', '.join(missing))


def safestorage_key():
    r = subprocess.run(
        ['security', 'find-generic-password', '-s', SAFE_STORAGE_SERVICE,
         '-a', SAFE_STORAGE_ACCOUNT, '-w'],
        capture_output=True, text=True)
    if r.returncode != 0:
        msg = (r.stderr or '').strip() or f'exit {r.returncode}'
        raise RuntimeError(f'failed to read Claude Safe Storage key: {msg}')
    pw = r.stdout.strip()
    return pbkdf2_hmac('sha1', pw.encode('utf8'), b'saltysalt', 1003, 16)


def _pkcs7_unpad(b):
    return b[:-b[-1]] if b else b


def _pkcs7_pad(b):
    n = 16 - (len(b) % 16)
    return b + bytes([n]) * n


def decrypt_blob(enc, key):
    if not enc or bytes(enc)[:3] != b'v10':
        return None
    enc = bytes(enc)
    dec = Cipher(algorithms.AES(key), modes.CBC(b' ' * 16)).decryptor()
    return _pkcs7_unpad(dec.update(enc[3:]) + dec.finalize())


def encrypt_blob(pt_bytes, key):
    enc = Cipher(algorithms.AES(key), modes.CBC(b' ' * 16)).encryptor()
    return b'v10' + enc.update(_pkcs7_pad(pt_bytes)) + enc.finalize()


def decrypt_cookie(enc, host, key):
    pt = decrypt_blob(enc, key)
    if pt is None:
        return None
    prefix = hashlib.sha256(host.encode()).digest()
    if len(pt) >= 32 and pt[:32] == prefix:
        pt = pt[32:]
    return pt.decode('utf8', 'replace')


def encrypt_cookie(value, host, key):
    pt = hashlib.sha256(host.encode()).digest() + str(value or '').encode('utf8')
    return encrypt_blob(pt, key)


def read_identity():
    claude_acct = (_read_json(CLAUDE_JSON, {}) or {}).get('oauthAccount') or {}
    return {
        'email': claude_acct.get('emailAddress'),
        'displayName': claude_acct.get('displayName'),
        'accountUuid': claude_acct.get('accountUuid'),
        'organizationUuid': claude_acct.get('organizationUuid'),
        'organizationName': claude_acct.get('organizationName'),
    }


def read_token_cache(key):
    enc = (_read_json(CONFIG_JSON, {}) or {}).get('oauth:tokenCache')
    if not enc:
        return None
    return json.loads(decrypt_blob(base64.b64decode(enc), key))


def write_token_cache(token_cache, key):
    if not token_cache:
        return False
    cfg = _read_json(CONFIG_JSON, {}) or {}
    pt = json.dumps(token_cache, separators=(',', ':')).encode('utf8')
    cfg['oauth:tokenCache'] = base64.b64encode(encrypt_blob(pt, key)).decode()
    _write_json(CONFIG_JSON, cfg)
    return True


def cmd_status():
    require_macos()
    print('Claude App:')
    print(f'  running      : {app_running()}')
    print(f'  support dir  : {SUPPORT}')
    print(f'  config       : {os.path.exists(CONFIG_JSON)}')
    print(f'  cookies      : {os.path.exists(COOKIES_DB)}')
    identity = read_identity()
    print(f'  identity     : {identity.get("displayName") or "unknown"} <{identity.get("email") or "unknown"}>')
    print(f'  vault        : {VAULT}')
    bundles = _bundles()
    print(f'  saved bundles: {len(bundles)}')


def cmd_capture(name):
    require_macos()
    require_app_files()
    log(f'=== capture "{name}" start ===')
    key = safestorage_key()
    os.makedirs(VAULT, exist_ok=True)

    tmp = COOKIES_DB + '.ccs-capture-tmp'
    shutil.copy2(COOKIES_DB, tmp)
    try:
        con = sqlite3.connect(tmp)
        rows = con.execute(
            f"select {','.join(COOKIE_COLS)} from cookies where host_key like '%claude.ai%'"
        ).fetchall()
        con.close()
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

    cookies = []
    for row in rows:
        rec = dict(zip(COOKIE_COLS, row))
        enc = rec.pop('encrypted_value')
        plain = rec.get('value') or ''
        if enc:
            plain = decrypt_cookie(enc, rec['host_key'], key) or plain
        rec['plaintext'] = plain
        rec['value'] = ''
        cookies.append(rec)

    token_cache = None
    try:
        token_cache = read_token_cache(key)
    except Exception as e:
        log(f'  tokenCache read skipped: {e}')

    bundle = {
        'schema': 1,
        'name': name,
        'captured_at': datetime.datetime.now().isoformat(timespec='seconds'),
        'identity': read_identity(),
        'cookies': cookies,
        'oauth_tokencache': token_cache,
    }
    path = _bundle_path(name)
    _write_json(path, bundle, 0o600)
    session_cookie = next((c for c in cookies if c.get('name') == 'sessionKey'), None)
    log(f'  saved {path}')
    log(f'  cookies={len(cookies)} sessionKey={"yes" if session_cookie else "no"} tokenCache={len(token_cache) if token_cache else 0}')
    log(f'=== capture "{name}" done ===')


def _backup_live():
    ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    d = os.path.join(BACKUPS, ts)
    os.makedirs(d, exist_ok=True)
    for src in (COOKIES_DB, CONFIG_JSON, CLAUDE_JSON):
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(d, os.path.basename(src)))
    os.makedirs(BACKUPS, exist_ok=True)
    with open(os.path.join(BACKUPS, 'LATEST'), 'w', encoding='utf8') as f:
        f.write(d)
    log(f'  backed up live files -> {d}')
    return d


def cmd_restore(name):
    require_macos()
    require_app_files()
    path = _bundle_path(name)
    if not os.path.exists(path):
        raise RuntimeError(f'bundle not found: {path}')
    if app_running():
        raise RuntimeError('Claude App is running; quit it completely first (Cmd+Q), then retry')

    bundle = _read_json(path)
    if not bundle:
        raise RuntimeError(f'bad bundle: {path}')
    key = safestorage_key()
    email = (bundle.get('identity') or {}).get('email')
    log(f'=== restore "{name}" ({email or "unknown"}) start ===')
    _backup_live()

    con = sqlite3.connect(COOKIES_DB)
    try:
        for c in bundle.get('cookies') or []:
            host = c['host_key']
            enc = encrypt_cookie(c.get('plaintext', ''), host, key)
            vals = []
            for col in COOKIE_COLS:
                if col == 'encrypted_value':
                    vals.append(sqlite3.Binary(enc))
                elif col == 'value':
                    vals.append('')
                else:
                    vals.append(c.get(col))
            placeholders = ','.join('?' * len(COOKIE_COLS))
            con.execute(f"INSERT OR REPLACE INTO cookies ({','.join(COOKIE_COLS)}) VALUES ({placeholders})", vals)
        con.commit()
        log(f'  restored {len(bundle.get("cookies") or [])} claude.ai cookies')
    finally:
        con.close()

    if write_token_cache(bundle.get('oauth_tokencache'), key):
        log(f'  restored oauth:tokenCache ({len(bundle.get("oauth_tokencache") or {})} slots)')

    if email:
        r = subprocess.run(['ccs', email], capture_output=True, text=True)
        if r.returncode == 0:
            log(f'  synced Claude Code layer with ccs {email}')
        else:
            msg = (r.stderr or r.stdout or '').strip().splitlines()[-1:] or ['unknown']
            log(f'  ccs sync skipped: {msg[0]}')

    log('=== restore done; reopen Claude App to verify ===')


def cmd_rollback():
    require_macos()
    if app_running():
        raise RuntimeError('Claude App is running; quit it completely first (Cmd+Q), then retry')
    latest = os.path.join(BACKUPS, 'LATEST')
    if not os.path.exists(latest):
        raise RuntimeError('no backup to roll back')
    d = open(latest, encoding='utf8').read().strip()
    log(f'=== rollback from {d} ===')
    for fname, dst in [('Cookies', COOKIES_DB), ('config.json', CONFIG_JSON), ('.claude.json', CLAUDE_JSON)]:
        src = os.path.join(d, fname)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            log(f'  restored {fname}')
    log('=== rollback done ===')


def _bundles():
    if not os.path.isdir(VAULT):
        return []
    return sorted(f for f in os.listdir(VAULT) if f.endswith('.json'))


def cmd_list():
    bundles = _bundles()
    if not bundles:
        print('(no Claude App bundles saved)')
        return
    for f in bundles:
        b = _read_json(os.path.join(VAULT, f), {}) or {}
        cookies = b.get('cookies') or []
        session_cookie = any(c.get('name') == 'sessionKey' for c in cookies)
        ident = b.get('identity') or {}
        print(f'  {f:40} email={ident.get("email")} cookies={len(cookies)} '
              f'sessionKey={"yes" if session_cookie else "no"} @ {b.get("captured_at")}')


def print_help():
    print(__doc__)
    print('Usage:')
    print('  ccs app status')
    print('  ccs app capture <name>')
    print('  ccs app list')
    print('  ccs app restore <name>   # alias: apply')
    print('  ccs app rollback')


def main():
    try:
        cmd = sys.argv[1] if len(sys.argv) > 1 else 'help'
        if cmd == 'status':
            cmd_status()
        elif cmd == 'capture' and len(sys.argv) > 2:
            cmd_capture(sys.argv[2])
        elif cmd == 'list':
            cmd_list()
        elif cmd in ('restore', 'apply') and len(sys.argv) > 2:
            cmd_restore(sys.argv[2])
        elif cmd == 'rollback':
            cmd_rollback()
        else:
            print_help()
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
