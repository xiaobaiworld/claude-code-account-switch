#!/usr/bin/env python3
"""
桌面客户端账号 capture / restore —— 验证「快照-恢复 cookie」方案是否可行。

⚠️ vault/ 里存的是真实会话密钥（sessionKey 等明文），已在 .gitignore 排除，绝不上传。
⚠️ restore 会写 Claude 的 Cookies / config.json，必须先退出 App。写前自动全量备份，可一键回滚。

用法：
  python3 desktop_switch.py capture <name>     # App 当前登录某账号时，抓它的完整可还原包
  python3 desktop_switch.py list                # 列出已抓的账号包
  python3 desktop_switch.py restore <name>      # 退出 App 后，把某账号的 cookie/token 写回
  python3 desktop_switch.py rollback            # 回滚到最近一次 restore 前的备份

机制（已实测验证）：
  - safeStorage 密钥：Keychain service='Claude Safe Storage' acct='Claude Key'
  - cookie 明文 = sha256(host_key)[32B] + 真实值；密文 = 'v10' + AES-128-CBC(key=PBKDF2(pw,'saltysalt',1003,16), IV=16空格)
  - config.json oauth:tokenCache = 同样 safeStorage 加密的 JSON
"""

import os
import re
import sys
import json
import time
import base64
import hashlib
import sqlite3
import shutil
import subprocess
import datetime
from hashlib import pbkdf2_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOME = os.path.expanduser('~')
SUPPORT = os.path.join(HOME, 'Library', 'Application Support', 'Claude')
CONFIG_JSON = os.path.join(SUPPORT, 'config.json')
COOKIES_DB = os.path.join(SUPPORT, 'Cookies')
CLAUDE_JSON = os.path.join(HOME, '.claude.json')

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.join(HERE, 'vault')
BACKUPS = os.path.join(HERE, 'backups')
LOG_PATH = os.path.join(HERE, 'probe.log')

SAFE_STORAGE_SERVICE = 'Claude Safe Storage'


def log(msg):
    ts = datetime.datetime.now().isoformat(timespec='seconds')
    line = f'[{ts}] [switch] {msg}'
    print(line)
    try:
        with open(LOG_PATH, 'a', encoding='utf8') as f:
            f.write(line + '\n')
    except Exception:
        pass


# ── 加解密 ──────────────────────────────────────────────────────────────────
def safestorage_key():
    r = subprocess.run(
        ['security', 'find-generic-password', '-s', SAFE_STORAGE_SERVICE, '-a', 'Claude Key', '-w'],
        capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'读取 Claude Safe Storage 密钥失败: {r.stderr.strip()}')
    pw = r.stdout.strip()
    return pbkdf2_hmac('sha1', pw.encode('utf8'), b'saltysalt', 1003, 16)


def _pkcs7_unpad(b):
    return b[:-b[-1]] if b else b


def _pkcs7_pad(b):
    n = 16 - (len(b) % 16)
    return b + bytes([n]) * n


def decrypt_blob(enc, key):
    """通用 safeStorage 解密，返回 bytes（不剥域名前缀）。"""
    if not enc or bytes(enc)[:3] != b'v10':
        return None
    enc = bytes(enc)
    dec = Cipher(algorithms.AES(key), modes.CBC(b' ' * 16)).decryptor()
    return _pkcs7_unpad(dec.update(enc[3:]) + dec.finalize())


def encrypt_blob(pt_bytes, key):
    enc = Cipher(algorithms.AES(key), modes.CBC(b' ' * 16)).encryptor()
    return b'v10' + enc.update(_pkcs7_pad(pt_bytes)) + enc.finalize()


def decrypt_cookie(enc, host, key):
    """cookie 明文 = sha256(host)[32B] + value。返回 value 字符串。"""
    pt = decrypt_blob(enc, key)
    if pt is None:
        return None
    if len(pt) >= 32 and pt[:32] == hashlib.sha256(host.encode()).digest():
        pt = pt[32:]
    return pt.decode('utf8', 'replace')


def encrypt_cookie(value, host, key):
    pt = hashlib.sha256(host.encode()).digest() + value.encode('utf8')
    return encrypt_blob(pt, key)


# ── App 运行检测 ─────────────────────────────────────────────────────────────
def app_running():
    r = subprocess.run(['pgrep', '-x', 'Claude'], capture_output=True, text=True)
    return r.returncode == 0


# ── capture ─────────────────────────────────────────────────────────────────
COOKIE_COLS = [
    'creation_utc', 'host_key', 'top_frame_site_key', 'name', 'value', 'encrypted_value',
    'path', 'expires_utc', 'is_secure', 'is_httponly', 'last_access_utc', 'has_expires',
    'is_persistent', 'priority', 'samesite', 'source_scheme', 'source_port', 'last_update_utc',
    'source_type', 'has_cross_site_ancestor',
]


def cmd_capture(name):
    log(f'=== capture "{name}" 开始 ===')
    key = safestorage_key()
    os.makedirs(VAULT, exist_ok=True)

    # cookies（全行，encrypted_value 解密成明文存）
    tmp = COOKIES_DB + '.captmp'
    shutil.copy(COOKIES_DB, tmp)
    con = sqlite3.connect(tmp)
    rows = con.execute(
        f"select {','.join(COOKIE_COLS)} from cookies where host_key like '%claude.ai%'"
    ).fetchall()
    con.close()
    os.remove(tmp)

    cookies = []
    for row in rows:
        rec = dict(zip(COOKIE_COLS, row))
        enc = rec.pop('encrypted_value')
        plain = rec.get('value') or ''
        if enc:
            plain = decrypt_cookie(enc, rec['host_key'], key) or plain
        rec['plaintext'] = plain
        rec['value'] = ''  # 还原时统一走加密
        cookies.append(rec)

    # tokenCache（解密成 JSON 对象存）
    token_cache = None
    try:
        enc = json.load(open(CONFIG_JSON)).get('oauth:tokenCache')
        if enc:
            token_cache = json.loads(decrypt_blob(base64.b64decode(enc), key))
    except Exception as e:
        log(f'  tokenCache 读取失败（可忽略）: {e}')

    # 共享层标识（仅记录身份，不存 keychain 明文——还原走 ccs）
    claude_acct = {}
    try:
        claude_acct = json.load(open(CLAUDE_JSON)).get('oauthAccount', {})
    except Exception:
        pass

    bundle = {
        'name': name,
        'captured_at': datetime.datetime.now().isoformat(timespec='seconds'),
        'identity': {
            'email': claude_acct.get('emailAddress'),
            'accountUuid': claude_acct.get('accountUuid'),
            'organizationUuid': claude_acct.get('organizationUuid'),
        },
        'cookies': cookies,
        'oauth_tokencache': token_cache,
    }
    path = os.path.join(VAULT, f'{_safe(name)}.json')
    json.dump(bundle, open(path, 'w', encoding='utf8'), indent=2, ensure_ascii=False)
    os.chmod(path, 0o600)
    sk = next((c for c in cookies if c['name'] == 'sessionKey'), None)
    log(f'  cookies={len(cookies)} sessionKey={"有" if sk else "无"} '
        f'tokenCache槽={len(token_cache) if token_cache else 0} email={bundle["identity"]["email"]}')
    log(f'  已保存 {path} (600)')
    log(f'=== capture "{name}" 完成 ===')


# ── restore ─────────────────────────────────────────────────────────────────
def _backup_live():
    ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    d = os.path.join(BACKUPS, ts)
    os.makedirs(d, exist_ok=True)
    for src in (COOKIES_DB, CONFIG_JSON, CLAUDE_JSON):
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(d, os.path.basename(src)))
    # 记录最近备份指针
    with open(os.path.join(BACKUPS, 'LATEST'), 'w') as f:
        f.write(d)
    log(f'  已备份 live 文件 -> {d}')
    return d


def cmd_restore(name):
    path = os.path.join(VAULT, f'{_safe(name)}.json')
    if not os.path.exists(path):
        log(f'找不到账号包: {path}'); return
    if app_running():
        log('⛔ Claude App 正在运行，请先完全退出（Cmd+Q）再 restore，否则会被 App 覆盖/损坏。')
        return
    bundle = json.load(open(path))
    key = safestorage_key()
    log(f'=== restore "{name}" ({bundle["identity"].get("email")}) 开始 ===')
    _backup_live()

    # 1. 写 cookies：整行 UPSERT，encrypted_value 用明文重新加密
    con = sqlite3.connect(COOKIES_DB)
    try:
        for c in bundle['cookies']:
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
        log(f'  已写入 {len(bundle["cookies"])} 条 claude.ai cookie')
    finally:
        con.close()

    # 2. 写 tokenCache 回 config.json
    if bundle.get('oauth_tokencache'):
        cfg = json.load(open(CONFIG_JSON))
        pt = json.dumps(bundle['oauth_tokencache'], separators=(',', ':')).encode('utf8')
        cfg['oauth:tokenCache'] = base64.b64encode(encrypt_blob(pt, key)).decode()
        tmp = CONFIG_JSON + '.tmp'
        json.dump(cfg, open(tmp, 'w'), ensure_ascii=False)
        os.replace(tmp, CONFIG_JSON)
        log(f'  已写回 oauth:tokenCache（{len(bundle["oauth_tokencache"])} 槽）')

    # 3. 共享层走 ccs（若账号名是 email 且 ccs 有该号）
    email = bundle['identity'].get('email')
    if email:
        r = subprocess.run(['ccs', email], capture_output=True, text=True)
        if r.returncode == 0:
            log(f'  已通过 ccs 切换共享层到 {email}')
        else:
            log(f'  ccs 切换共享层失败（可手动 ccs {email}）: {r.stderr.strip()[:120]}')

    log(f'=== restore "{name}" 完成。请重开 Claude App 验证 ===')


def cmd_rollback():
    latest = os.path.join(BACKUPS, 'LATEST')
    if not os.path.exists(latest):
        log('无备份可回滚'); return
    if app_running():
        log('⛔ 请先退出 Claude App 再回滚'); return
    d = open(latest).read().strip()
    log(f'=== rollback 从 {d} ===')
    for fname, dst in [('Cookies', COOKIES_DB), ('config.json', CONFIG_JSON), ('.claude.json', CLAUDE_JSON)]:
        src = os.path.join(d, fname)
        if os.path.exists(src):
            shutil.copy2(src, dst)
            log(f'  已恢复 {fname}')
    log('=== rollback 完成 ===')


def cmd_list():
    if not os.path.isdir(VAULT):
        print('（vault 为空）'); return
    for f in sorted(os.listdir(VAULT)):
        if f.endswith('.json'):
            b = json.load(open(os.path.join(VAULT, f)))
            sk = any(c['name'] == 'sessionKey' for c in b.get('cookies', []))
            print(f"  {f:40} email={b['identity'].get('email')} cookies={len(b.get('cookies',[]))} "
                  f"sessionKey={'有' if sk else '无'} @ {b.get('captured_at')}")


def _safe(name):
    return re.sub(r'[^A-Za-z0-9.@_-]', '_', name)


def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    cmd = sys.argv[1]
    if cmd == 'capture' and len(sys.argv) > 2:
        cmd_capture(sys.argv[2])
    elif cmd == 'restore' and len(sys.argv) > 2:
        cmd_restore(sys.argv[2])
    elif cmd == 'rollback':
        cmd_rollback()
    elif cmd == 'list':
        cmd_list()
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
