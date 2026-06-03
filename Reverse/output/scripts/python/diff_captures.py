"""
diff_captures.py — 对比两次高德抓包，找出风控字段差异
用法：
    python diff_captures.py samples/capture_A.json samples/capture_B.json
    python diff_captures.py samples/capture_A.json samples/capture_B.json --risk-only
    python diff_captures.py samples/capture_A.json samples/capture_B.json --url-filter um.json

输出：
    - 只在 A 或 B 中出现的 URL（新增/消失的请求）
    - 相同 URL 的请求体 diff（风控上报字段变化）
    - 标注 [设备相关] / [账号相关] / [固定] 维度
"""

import sys
import json
import argparse
import difflib
import re
from pathlib import Path

# ── 维度判断规则（按关键词猜）───────────────────────────────
DEVICE_KEYWORDS  = ['udid', 'imei', 'imsi', 'idfv', 'idfa', 'did', 'device',
                    'model', 'brand', 'mac', 'hardware', 'fingerprint', 'tid',
                    'umid', 'adid', 'gd_amap', 'vimei', 'vimsi']
ACCOUNT_KEYWORDS = ['token', 'uid', 'userid', 'user_id', 'session', 'login',
                    'auth', 'cookie', 'ticket', 'credit', 'openid', 'nick']


def load(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    return data.get('flows', [])


def normalize_url(url: str) -> str:
    # 去掉 query string 里的时间戳/nonce，便于 URL 匹配
    url = re.sub(r'[?&](t|ts|time|timestamp|nonce|_)=\d+', '', url)
    return url.split('?')[0]


def guess_dim(key: str) -> str:
    kl = key.lower()
    for kw in DEVICE_KEYWORDS:
        if kw in kl:
            return '[设备相关]'
    for kw in ACCOUNT_KEYWORDS:
        if kw in kl:
            return '[账号相关]'
    return '[固定?]'


def extract_kv(body: str) -> dict:
    """尝试从 JSON / query string 中提取 key=value 对"""
    result = {}
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            _flatten(obj, '', result)
            return result
    except Exception:
        pass
    for pair in re.split(r'&|\n', body):
        if '=' in pair:
            k, _, v = pair.partition('=')
            result[k.strip()] = v.strip()
    return result


def _flatten(obj, prefix: str, out: dict):
    if isinstance(obj, dict):
        for k, v in obj.items():
            _flatten(v, f'{prefix}.{k}' if prefix else k, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _flatten(v, f'{prefix}[{i}]', out)
    else:
        out[prefix] = str(obj)


def match_flows(flows_a: list, flows_b: list, url_filter: str = '', risk_only: bool = False):
    def key(f):
        return normalize_url(f['request']['url'])

    def keep(f):
        if risk_only and not f.get('is_risk'):
            return False
        if url_filter and url_filter.lower() not in f['request']['url'].lower():
            return False
        return True

    a_dict = {key(f): f for f in flows_a if keep(f)}
    b_dict = {key(f): f for f in flows_b if keep(f)}

    only_a = set(a_dict) - set(b_dict)
    only_b = set(b_dict) - set(a_dict)
    common = set(a_dict) & set(b_dict)
    return a_dict, b_dict, only_a, only_b, common


def print_diff(url: str, body_a: str, body_b: str):
    kv_a = extract_kv(body_a)
    kv_b = extract_kv(body_b)
    all_keys = sorted(set(kv_a) | set(kv_b))

    changed = False
    for k in all_keys:
        va = kv_a.get(k, '<<MISSING>>')
        vb = kv_b.get(k, '<<MISSING>>')
        if va != vb:
            dim = guess_dim(k)
            changed = True
            print(f'    {dim} {k}')
            print(f'      A: {va[:100]}')
            print(f'      B: {vb[:100]}')

    if not changed and body_a != body_b:
        # 做文本 diff 兜底
        diff = list(difflib.unified_diff(
            body_a.splitlines(), body_b.splitlines(),
            fromfile='A', tofile='B', lineterm=''
        ))
        for line in diff[:40]:
            print('    ' + line)


def main():
    parser = argparse.ArgumentParser(description='对比两次高德抓包')
    parser.add_argument('file_a',        help='capture_A.json')
    parser.add_argument('file_b',        help='capture_B.json')
    parser.add_argument('--risk-only',   action='store_true', help='只看风控请求')
    parser.add_argument('--url-filter',  default='',          help='只看含该字符串的 URL')
    args = parser.parse_args()

    flows_a = load(args.file_a)
    flows_b = load(args.file_b)
    print(f'[diff] A: {len(flows_a)} 条  B: {len(flows_b)} 条')

    a_dict, b_dict, only_a, only_b, common = match_flows(
        flows_a, flows_b, args.url_filter, args.risk_only
    )

    if only_a:
        print(f'\n=== 只在 A 中出现的请求 ({len(only_a)} 条) ===')
        for u in sorted(only_a):
            print(f'  - {u}')

    if only_b:
        print(f'\n=== 只在 B 中出现的请求 ({len(only_b)} 条) ===')
        for u in sorted(only_b):
            print(f'  + {u}')

    if common:
        print(f'\n=== 共同请求中的字段差异 ({len(common)} 条) ===')
        for u in sorted(common):
            fa = a_dict[u]
            fb = b_dict[u]
            body_a = fa['request']['body']
            body_b = fb['request']['body']
            tag = ' [RISK]' if fa.get('is_risk') else ''
            if body_a == body_b:
                continue
            print(f'\n  {u}{tag}')
            print_diff(u, body_a, body_b)

    # 汇总风控上报接口
    risk_a = [f for f in flows_a if f.get('is_risk')]
    risk_b = [f for f in flows_b if f.get('is_risk')]
    print(f'\n=== 风控请求汇总 ===')
    print(f'  A: {len(risk_a)} 条风控请求')
    print(f'  B: {len(risk_b)} 条风控请求')
    all_risk_urls = sorted({normalize_url(f['request']['url']) for f in risk_a + risk_b})
    for u in all_risk_urls:
        in_a = any(normalize_url(f['request']['url']) == u for f in risk_a)
        in_b = any(normalize_url(f['request']['url']) == u for f in risk_b)
        flag = ' (A+B)' if in_a and in_b else (' (A only)' if in_a else ' (B only)')
        print(f'  {u}{flag}')


if __name__ == '__main__':
    main()
