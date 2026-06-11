#!/usr/bin/env python3
"""
桌面客户端账号体系 —— 只读探针。

目的：在 Claude 桌面客户端切换账号「之前 / 之后」各跑一次 snapshot，
再用 diff 看到底是哪些文件 / 字段 / keychain 在变化，从而搞清楚
「当前激活账号」这个指针到底存在哪里。

安全约束（重要）：
  - 全程只读，绝不修改任何客户端文件 / keychain / cookie。
  - 敏感值（token / sessionKey / refreshToken）一律只记录 sha256 指纹前12位 + 末4位，
    绝不把明文写进快照或日志。
  - 日志写到 probe/probe.log，记录每一步动了哪个源、成功与否。

用法：
  python3 desktop_probe.py snapshot before     # 切换前
  # —— 在桌面客户端里切换到另一个账号 ——
  python3 desktop_probe.py snapshot after      # 切换后
  python3 desktop_probe.py diff                 # 对比最近两次
  python3 desktop_probe.py diff before after    # 对比指定两次
  python3 desktop_probe.py list                 # 列出已有快照
"""

import os
import re
import sys
import json
import base64
import hashlib
import sqlite3
import shutil
import tempfile
import subprocess
import datetime

HOME = os.path.expanduser('~')
SUPPORT = os.path.join(HOME, 'Library', 'Application Support', 'Claude')
CONFIG_JSON = os.path.join(SUPPORT, 'config.json')
COOKIES_DB = os.path.join(SUPPORT, 'Cookies')
LEVELDB = os.path.join(SUPPORT, 'Local Storage', 'leveldb')
CLAUDE_JSON = os.path.join(HOME, '.claude.json')

HERE = os.path.dirname(os.path.abspath(__file__))
SNAP_DIR = os.path.join(HERE, 'snapshots')
LOG_PATH = os.path.join(HERE, 'probe.log')

SAFE_STORAGE_SERVICE = 'Claude Safe Storage'
CC_CRED_SERVICE = 'Claude Code-credentials'


# ── 日志 ──────────────────────────────────────────────────────────────────
def log(msg):
    ts = datetime.datetime.now().isoformat(timespec='seconds')
    line = f'[{ts}] {msg}'
    print(line)
    try:
        with open(LOG_PATH, 'a', encoding='utf8') as f:
            f.write(line + '\n')
    except Exception:
        pass


# ── 脱敏 ──────────────────────────────────────────────────────────────────
def fp(value):
    """敏感值 -> 指纹。绝不返回明文。"""
    if value is None:
        return None
    if not isinstance(value, (str, bytes)):
        value = str(value)
    b = value.encode('utf8') if isinstance(value, str) else value
    h = hashlib.sha256(b).hexdigest()[:12]
    tail = value[-4:] if isinstance(value, str) and len(value) > 4 else '?'
    return f'sha256:{h}..{tail}(len={len(value)})'


# ── keychain ──────────────────────────────────────────────────────────────
def keychain_read(service, accounts=('Claude Key', 'Claude', os.getlogin(), '')):
    for acct in accounts:
        args = ['security', 'find-generic-password', '-s', service]
        if acct:
            args += ['-a', acct]
        args += ['-w']
        r = subprocess.run(args, capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.rstrip('\n'), acct
    return None, None


def decrypt_safestorage(b64_value, key_pw):
    """Chromium OSCrypt v10 (macOS) = AES-128-CBC, key=PBKDF2(pw,'saltysalt',1003,16), iv=16空格。"""
    from hashlib import pbkdf2_hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = pbkdf2_hmac('sha1', key_pw.encode('utf8'), b'saltysalt', 1003, 16)
    raw = base64.b64decode(b64_value)
    if raw[:3] != b'v10':
        raise ValueError(f'unexpected prefix {raw[:3]!r}')
    dec = Cipher(algorithms.AES(key), modes.CBC(b' ' * 16)).decryptor()
    pt = dec.update(raw[3:]) + dec.finalize()
    pt = pt[:-pt[-1]]  # PKCS7 unpad
    return json.loads(pt)


# ── 各数据源采集 ────────────────────────────────────────────────────────────
def snap_oauth_tokencache():
    """config.json 的 oauth:tokenCache —— 多账号 token map。"""
    out = {'present': False, 'accounts': []}
    try:
        cfg = json.load(open(CONFIG_JSON))
    except Exception as e:
        log(f'  config.json 读取失败: {e}')
        return out
    enc = cfg.get('oauth:tokenCache')
    if not enc:
        log('  config.json 无 oauth:tokenCache')
        return out
    out['present'] = True
    out['raw_fp'] = fp(enc)
    pw, acct = keychain_read(SAFE_STORAGE_SERVICE)
    if not pw:
        log('  Claude Safe Storage 密钥读取失败，只记录密文指纹')
        return out
    try:
        obj = decrypt_safestorage(enc, pw)
    except Exception as e:
        log(f'  oauth:tokenCache 解密失败: {e}')
        return out
    # obj 是 { "uuid:org:url:scopes": {token,refreshToken,expiresAt,subscriptionType,...} }
    for k, v in (obj.items() if isinstance(obj, dict) else []):
        parts = k.split(':')
        entry = {
            'key_account_uuid': parts[0] if len(parts) > 0 else None,
            'key_org_uuid': parts[1] if len(parts) > 1 else None,
            'key_full_fp': fp(k),
        }
        if isinstance(v, dict):
            entry.update({
                'token_fp': fp(v.get('token')),
                'refreshToken_fp': fp(v.get('refreshToken')),
                'expiresAt': v.get('expiresAt'),
                'subscriptionType': v.get('subscriptionType'),
                'rateLimitTier': v.get('rateLimitTier'),
            })
        out['accounts'].append(entry)
    out['account_count'] = len(out['accounts'])
    out['key_order'] = [a['key_account_uuid'] for a in out['accounts']]
    log(f'  oauth:tokenCache 解密成功，{out["account_count"]} 个账号槽')
    return out


def snap_config_other():
    """config.json 里其它可能跟"当前账号"有关的键（只记键名 + 值指纹）。"""
    out = {}
    try:
        cfg = json.load(open(CONFIG_JSON))
    except Exception:
        return out
    interesting = re.compile(r'(account|user|active|current|org|oauth|session|login|profile)', re.I)
    for k, v in cfg.items():
        if k == 'oauth:tokenCache':
            continue
        if interesting.search(k):
            out[k] = fp(v) if isinstance(v, str) and len(v) > 12 else v
    out['_config_mtime'] = _mtime(CONFIG_JSON)
    return out


def snap_claude_json():
    out = {}
    try:
        d = json.load(open(CLAUDE_JSON))
    except Exception:
        return {'present': False}
    out['present'] = True
    out['userID'] = fp(d.get('userID')) if d.get('userID') else None
    oa = d.get('oauthAccount') or {}
    out['oauthAccount'] = {
        'emailAddress': oa.get('emailAddress'),  # 邮箱是身份标识，保留明文便于辨认账号
        'organizationName': oa.get('organizationName'),
        'accountUuid': oa.get('accountUuid'),
        'organizationUuid': oa.get('organizationUuid'),
    }
    out['_mtime'] = _mtime(CLAUDE_JSON)
    return out


def decrypt_cookie(enc_value, key_pw):
    """Chromium cookie encrypted_value(macOS v10) = AES-128-CBC，同 safeStorage 密钥。
    新版 Chromium 会在明文前加 32 字节域名 SHA256，解出后若前 32 字节非可打印则剥掉。"""
    from hashlib import pbkdf2_hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if not enc_value or enc_value[:3] != b'v10':
        return None
    key = pbkdf2_hmac('sha1', key_pw.encode('utf8'), b'saltysalt', 1003, 16)
    dec = Cipher(algorithms.AES(key), modes.CBC(b' ' * 16)).decryptor()
    pt = dec.update(enc_value[3:]) + dec.finalize()
    if pt:
        pt = pt[:-pt[-1]]  # PKCS7
    # 剥掉可能的 32 字节域名哈希前缀
    if len(pt) > 32 and not all(32 <= b < 127 for b in pt[:8]):
        pt = pt[32:]
    try:
        return pt.decode('utf8')
    except Exception:
        return pt.hex()


def snap_cookies():
    """claude.ai 会话 cookie。真实值在 encrypted_value（safeStorage 加密）。
    - 凭证类(sessionKey 等)：记 encrypted_value 指纹，用于检测变化，不存明文。
    - 身份指针类(lastActiveOrg/ajs_user_id)：解密后存明文，便于辨认激活账号。"""
    out = {'cookies': {}}
    if not os.path.exists(COOKIES_DB):
        return {'present': False}
    tmp = tempfile.mktemp(suffix='.sqlite')
    try:
        shutil.copy(COOKIES_DB, tmp)
        con = sqlite3.connect(tmp)
        rows = con.execute(
            "select host_key,name,encrypted_value,last_update_utc "
            "from cookies where host_key like '%claude.ai%'"
        ).fetchall()
        con.close()
    except Exception as e:
        log(f'  cookies 读取失败: {e}')
        return {'present': False, 'error': str(e)}
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass

    pw, _ = keychain_read(SAFE_STORAGE_SERVICE)
    identity_plain = {'lastActiveOrg', 'ajs_user_id', 'ajs_anonymous_id'}
    for host, name, enc, upd in rows:
        enc = bytes(enc) if enc else b''
        rec = {'enc_fp': fp(enc.hex()) if enc else None, 'last_update': upd}
        if name in identity_plain and pw and enc:
            try:
                rec['value'] = decrypt_cookie(enc, pw)
            except Exception as e:
                rec['decrypt_err'] = str(e)
        out['cookies'][name] = rec
    out['present'] = True
    out['_mtime'] = _mtime(COOKIES_DB)
    return out


def snap_leveldb():
    """Local Storage leveldb —— 扫描可打印 key，找含 account/user/org 的项。文件级记 mtime+sha。"""
    out = {'files': {}, 'interesting_keys': []}
    if not os.path.isdir(LEVELDB):
        return {'present': False}
    for fn in sorted(os.listdir(LEVELDB)):
        p = os.path.join(LEVELDB, fn)
        if not os.path.isfile(p):
            continue
        out['files'][fn] = {'mtime': _mtime(p), 'size': os.path.getsize(p)}
    # 粗扫 .ldb/.log 里的可打印字符串，找身份相关 key（只记 key 名，不记 value）
    pat = re.compile(rb'[\x20-\x7e]{6,}')
    want = re.compile(rb'(account|user|org|email|active|current|session|profile)', re.I)
    uuid_re = re.compile(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
    email_re = re.compile(rb'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
    found = set()
    uuids = set()
    emails = set()
    for fn, meta in out['files'].items():
        if not (fn.endswith('.ldb') or fn.endswith('.log')):
            continue
        try:
            data = open(os.path.join(LEVELDB, fn), 'rb').read()
        except Exception:
            continue
        for m in pat.findall(data):
            if want.search(m) and len(m) < 120:
                found.add(m.decode('ascii', 'replace'))
        for u in uuid_re.findall(data):
            uuids.add(u.decode())
        for e in email_re.findall(data):
            emails.add(e.decode())
    out['interesting_keys'] = sorted(found)[:80]
    # 这两个是定位"激活账号"的关键证据：webview 持久层里出现的所有账号 UUID / 邮箱
    out['uuids_present'] = sorted(uuids)
    out['emails_present'] = sorted(emails)
    out['present'] = True
    return out


def snap_keychain_cc():
    """CLI 用的 Claude Code-credentials（明文 keychain），记其身份指纹便于和桌面端对比。"""
    val, acct = keychain_read(CC_CRED_SERVICE, accounts=(os.getlogin(), 'Claude Key', ''))
    if val is None:
        return {'present': False}
    try:
        d = json.loads(val)
        o = d.get('claudeAiOauth') or {}
        return {
            'present': True,
            'keychain_acct': acct,
            'accessToken_fp': fp(o.get('accessToken')),
            'refreshToken_fp': fp(o.get('refreshToken')),
            'expiresAt': o.get('expiresAt'),
            'subscriptionType': o.get('subscriptionType'),
        }
    except Exception as e:
        return {'present': True, 'parse_error': str(e), 'raw_fp': fp(val)}


def _mtime(path):
    try:
        return datetime.datetime.fromtimestamp(os.path.getmtime(path)).isoformat(timespec='seconds')
    except Exception:
        return None


# ── 命令 ──────────────────────────────────────────────────────────────────
def cmd_snapshot(label):
    log(f'=== snapshot "{label}" 开始 ===')
    snap = {
        'label': label,
        'taken_at': datetime.datetime.now().isoformat(timespec='seconds'),
        'oauth_tokencache': snap_oauth_tokencache(),
        'config_other': snap_config_other(),
        'claude_json': snap_claude_json(),
        'cookies': snap_cookies(),
        'leveldb': snap_leveldb(),
        'keychain_cc': snap_keychain_cc(),
    }
    os.makedirs(SNAP_DIR, exist_ok=True)
    idx = len([f for f in os.listdir(SNAP_DIR) if f.endswith('.json')])
    fname = f'{idx:03d}-{label}.json'
    path = os.path.join(SNAP_DIR, fname)
    json.dump(snap, open(path, 'w', encoding='utf8'), indent=2, ensure_ascii=False)
    log(f'  已保存 {fname}')
    log(f'=== snapshot "{label}" 完成 ===')
    # 摘要
    tc = snap['oauth_tokencache']
    print(f'\n摘要: tokenCache 账号槽={tc.get("account_count")} | '
          f'cookie sessionKey={"有" if "sessionKey" in snap["cookies"].get("cookies",{}) else "无"} | '
          f'lastActiveOrg={snap["cookies"].get("cookies",{}).get("lastActiveOrg",{}).get("value")}')


def _load_snaps():
    files = sorted(f for f in os.listdir(SNAP_DIR) if f.endswith('.json')) if os.path.isdir(SNAP_DIR) else []
    return files


def _find_snap(label_or_file):
    for f in _load_snaps():
        if f == label_or_file or f.endswith(f'-{label_or_file}.json') or f.startswith(label_or_file):
            return os.path.join(SNAP_DIR, f)
    return None


def _flatten(obj, prefix=''):
    flat = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            flat.update(_flatten(v, f'{prefix}.{k}' if prefix else k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            flat.update(_flatten(v, f'{prefix}[{i}]'))
    else:
        flat[prefix] = obj
    return flat


def cmd_diff(a=None, b=None):
    snaps = _load_snaps()
    if len(snaps) < 2 and not (a and b):
        log('快照不足两个，无法 diff')
        return
    pa = _find_snap(a) if a else os.path.join(SNAP_DIR, snaps[-2])
    pb = _find_snap(b) if b else os.path.join(SNAP_DIR, snaps[-1])
    if not pa or not pb:
        log(f'找不到快照: a={a} b={b}')
        return
    log(f'=== diff {os.path.basename(pa)}  ->  {os.path.basename(pb)} ===')
    fa = _flatten(json.load(open(pa)))
    fb = _flatten(json.load(open(pb)))
    keys = sorted(set(fa) | set(fb))
    # 忽略噪声字段
    ignore = re.compile(r'(taken_at|label|_mtime|last_update|mtime|\.size$)')
    changed = []
    for k in keys:
        if ignore.search(k):
            continue
        va, vb = fa.get(k, '∅'), fb.get(k, '∅')
        if va != vb:
            changed.append((k, va, vb))
    if not changed:
        print('  (除时间戳/mtime 外无变化)')
    else:
        print(f'  {len(changed)} 处变化（已过滤纯时间戳噪声）:\n')
        for k, va, vb in changed:
            print(f'  ● {k}')
            print(f'      before: {va}')
            print(f'      after : {vb}')
    # 单独把 mtime 变化列出来（哪些文件被动过）
    print('\n  —— 文件 mtime 变化（说明客户端写过这些文件）——')
    for k in keys:
        if k.endswith('_mtime') or k.endswith('.mtime'):
            va, vb = fa.get(k), fb.get(k)
            if va != vb:
                print(f'  ~ {k}: {va} -> {vb}')
    log('=== diff 完成 ===')


def cmd_list():
    for f in _load_snaps():
        print(' ', f)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == 'snapshot':
        cmd_snapshot(sys.argv[2] if len(sys.argv) > 2 else 'snap')
    elif cmd == 'diff':
        cmd_diff(*sys.argv[2:4])
    elif cmd == 'list':
        cmd_list()
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
