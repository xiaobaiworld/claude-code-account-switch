"""Anthropic OAuth 端点的 HTTP 客户端 helper（共享 Cloudflare cookie jar）。

为什么需要：
  Cloudflare 边缘对 fresh client（无 _cfuvid cookie）会先返一次 429 + Set-Cookie，
  带着 cookie 的下次请求才放行。状态栏因为 Claude Code 长进程内 urllib 重用
  cookie 没踩到这个坑；但守护进程每次 spawn 新 Python 进程都是 fresh client，
  几乎必撞 429 然后被 v3.10.0 的乒乓 bug 放大。

  此 helper 把 cookie 持久化到 ~/.ccs/cf-cookies.txt，所有 monitor/状态栏/CLI
  共用。首次访问可能踩到一次 429 + cookie 下发，之后稳定 200。

用法：
    from anthropic_http import request_anthropic
    code, body, headers = request_anthropic(
        'https://api.anthropic.com/api/oauth/usage', token)
    # code: HTTP 状态码（int），网络错误时为 None
    # body: bytes
    # headers: dict[str, str]（含 'anthropic-organization-id' 用于区分真 429 vs Cloudflare 429）
"""
import os
import time
import urllib.request
import urllib.error
import http.cookiejar

COOKIE_FILE = os.path.expanduser('~/.ccs/cf-cookies.txt')

_jar = None
_opener = None


def _get_opener():
    global _jar, _opener
    if _opener is not None:
        return _opener
    os.makedirs(os.path.dirname(COOKIE_FILE), exist_ok=True)
    _jar = http.cookiejar.MozillaCookieJar(COOKIE_FILE)
    try:
        _jar.load(ignore_discard=True, ignore_expires=True)
    except (FileNotFoundError, http.cookiejar.LoadError):
        pass
    _opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_jar))
    return _opener


def _save_jar():
    if _jar is None:
        return
    try:
        _jar.save(ignore_discard=True, ignore_expires=True)
    except Exception:
        pass


def request_anthropic(url, token, timeout=8, beta='oauth-2025-04-20',
                      retry_on_cf_429=True):
    """请求 Anthropic OAuth 端点。返回 (code:int|None, body:bytes, headers:dict)。

    - retry_on_cf_429=True 时，若首次拿到 Cloudflare 429（响应头里没有
      'anthropic-organization-id'，意味着没到 Anthropic 后端），自动重试一次
      （此时新的 _cfuvid 已被 jar 收纳）。真用尽的 429 不重试，原样返回。
    """
    opener = _get_opener()
    req = urllib.request.Request(url, headers={
        'Authorization': f'Bearer {token}',
        'anthropic-beta': beta,
        'Accept': 'application/json',
    })
    attempts = 2 if retry_on_cf_429 else 1
    last_code, last_body, last_headers = None, b'', {}
    for i in range(attempts):
        try:
            r = opener.open(req, timeout=timeout)
            body = r.read()
            headers = dict(r.getheaders())
            _save_jar()
            return r.getcode(), body, headers
        except urllib.error.HTTPError as e:
            body = e.read() if hasattr(e, 'read') else b''
            headers = dict(e.headers.items()) if e.headers else {}
            _save_jar()  # 即使 429 也保存：Cloudflare 已下发 _cfuvid
            last_code, last_body, last_headers = e.code, body, headers
            if e.code == 429 and 'anthropic-organization-id' not in headers and i + 1 < attempts:
                time.sleep(0.3)
                continue
            return e.code, body, headers
        except Exception:
            return None, b'', {}
    return last_code, last_body, last_headers


def is_real_anthropic_429(headers):
    """429 时区分：True=Anthropic 后端确认的限速（含真用尽），False=Cloudflare 边缘拦截"""
    return 'anthropic-organization-id' in (headers or {})
