"""
auto_capture.py — 全自动两轮抓包
Round 1: bypass only（真实设备指纹）→ samples/capture_real.json
Round 2: bypass + spoof（伪装新机）   → samples/capture_spoofed.json
不需要代理/CA 证书，直接在 App 层捕获明文请求
"""

import frida
import sys
import json
import time
import io
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

DEVICE_ID  = 'fcb0b05ae20229767149e98cb3ac94dcde52f74f'
BUNDLE_ID  = 'com.autonavi.amap'
SCRIPT_DIR = Path(__file__).parent.parent / 'frida'
SAMPLES    = Path(__file__).parent.parent.parent / 'samples'
CAPTURE_SECS = 45


def load_js(name: str) -> str:
    return (SCRIPT_DIR / name).read_text(encoding='utf-8')


def run_round(dev, label: str, script_names: list[str]) -> list[dict]:
    print(f'\n[auto_capture] === Round {label} ===')
    print(f'[auto_capture] 加载: {script_names}')

    pid = dev.spawn([BUNDLE_ID])
    session = dev.attach(pid)
    requests: list[dict] = []
    detached = [False]

    def on_detach(reason, crash):
        detached[0] = True
        print(f'[auto_capture] session detached: {reason}')

    session.on('detached', on_detach)

    def on_msg(msg, _data):
        if msg.get('type') != 'send':
            return
        payload = msg.get('payload', {})
        if not isinstance(payload, dict):
            return
        if payload.get('type') == 'request':
            requests.append(payload)
            tag = '[RISK]' if payload.get('is_risk') else '[REQ ]'
            print(f'  {tag} {payload.get("method","?")} {payload.get("url","")[:80]}')
        elif payload.get('type') == 'idfv':
            print(f'  [IDFV] {payload.get("value")}')

    # 合并成单个脚本一次性加载，避免多脚本 session 竞态问题
    combined = '\n\n'.join(load_js(name) for name in script_names)
    try:
        s = session.create_script(combined)
        s.on('message', on_msg)
        s.load()
    except Exception as e:
        print(f'[auto_capture] WARN 脚本加载失败: {e}')
        return requests

    dev.resume(pid)
    print(f'[auto_capture] App 已 resume，等待 {CAPTURE_SECS} 秒...')

    deadline = time.time() + CAPTURE_SECS
    while time.time() < deadline and not detached[0]:
        time.sleep(1)

    try:
        session.detach()
    except Exception:
        pass
    try:
        dev.kill(pid)
    except Exception:
        pass

    print(f'[auto_capture] Round {label} 完成，捕获 {len(requests)} 条请求')
    return requests


def main():
    SAMPLES.mkdir(parents=True, exist_ok=True)
    dev = frida.get_device(DEVICE_ID)

    # Round 1：真实设备（无 spoof）
    real = run_round(dev, 'A-真实设备', [
        'bypass.js',
        'debug/net_capture.js',
    ])
    real_path = SAMPLES / 'capture_real.json'
    real_path.write_text(
        json.dumps({'label': 'real', 'flows': real}, indent=2, ensure_ascii=False),
        encoding='utf-8'
    )
    print(f'[auto_capture] 已保存: {real_path}')

    # 两轮之间等待，让 frida-server 和系统进程完全清理
    print('\n[auto_capture] 等待 15 秒后开始 Round B...')
    time.sleep(15)
    # 重新获取设备引用，确保连接状态干净
    dev = frida.get_device(DEVICE_ID)

    # Round 2：伪装新机（加 spoof.js）
    spoofed = run_round(dev, 'B-伪装新机', [
        'bypass.js',
        'spoof.js',
        'debug/net_capture.js',
    ])
    sp_path = SAMPLES / 'capture_spoofed.json'
    sp_path.write_text(
        json.dumps({'label': 'spoofed', 'flows': spoofed}, indent=2, ensure_ascii=False),
        encoding='utf-8'
    )
    print(f'[auto_capture] 已保存: {sp_path}')

    # 自动 diff
    print('\n[auto_capture] === Diff 分析 ===')
    diff_results = diff(real, spoofed)
    diff_path = SAMPLES / 'diff_result.json'
    diff_path.write_text(
        json.dumps(diff_results, indent=2, ensure_ascii=False),
        encoding='utf-8'
    )
    print_diff(diff_results)
    print(f'\n[auto_capture] diff 已保存: {diff_path}')


# ── 内联 diff 逻辑 ───────────────────────────────────────────
import re

DEVICE_KW  = ['udid', 'imei', 'imsi', 'idfv', 'idfa', 'did', 'device',
               'model', 'mac', 'hardware', 'fingerprint', 'tid', 'umid',
               'adid', 'gd_amap', 'vimei', 'vimsi']
ACCOUNT_KW = ['token', 'uid', 'userid', 'session', 'login', 'auth',
               'cookie', 'ticket', 'credit', 'openid']


def guess_dim(key: str) -> str:
    kl = key.lower()
    for kw in DEVICE_KW:
        if kw in kl:
            return '[设备相关]'
    for kw in ACCOUNT_KW:
        if kw in kl:
            return '[账号相关]'
    return '[固定?]  '


def norm_url(url: str) -> str:
    return re.sub(r'[?&](t|ts|time|timestamp|nonce|_)=\d+', '', url).split('?')[0]


def flatten(obj, prefix='', out=None):
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f'{prefix}.{k}' if prefix else k, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            flatten(v, f'{prefix}[{i}]', out)
    else:
        out[prefix] = str(obj)
    return out


def parse_body(body: str) -> dict:
    try:
        return flatten(json.loads(body))
    except Exception:
        result = {}
        for pair in re.split(r'&|\n', body):
            if '=' in pair:
                k, _, v = pair.partition('=')
                result[k.strip()] = v.strip()
        return result


def diff(flows_a: list, flows_b: list) -> dict:
    a_map = {norm_url(f['url']): f for f in flows_a}
    b_map = {norm_url(f['url']): f for f in flows_b}

    only_a = sorted(set(a_map) - set(b_map))
    only_b = sorted(set(b_map) - set(a_map))
    common_diffs = []

    for url in sorted(set(a_map) & set(b_map)):
        ba = parse_body(a_map[url]['body'])
        bb = parse_body(b_map[url]['body'])
        all_keys = sorted(set(ba) | set(bb))
        changes = []
        for k in all_keys:
            va = ba.get(k, '<<MISSING>>')
            vb = bb.get(k, '<<MISSING>>')
            if va != vb:
                changes.append({'key': k, 'dim': guess_dim(k), 'A': va[:120], 'B': vb[:120]})
        if changes:
            common_diffs.append({
                'url':     url,
                'is_risk': a_map[url].get('is_risk', False),
                'changes': changes,
            })

    return {'only_A': only_a, 'only_B': only_b, 'common_diffs': common_diffs}


def print_diff(d: dict):
    if d['only_A']:
        print(f"\n只在真实设备出现的请求 ({len(d['only_A'])} 条):")
        for u in d['only_A']:
            print(f'  - {u}')
    if d['only_B']:
        print(f"\n只在伪装设备出现的请求 ({len(d['only_B'])} 条):")
        for u in d['only_B']:
            print(f'  + {u}')
    if d['common_diffs']:
        print(f"\n字段差异 ({len(d['common_diffs'])} 个接口有变化):")
        for entry in d['common_diffs']:
            tag = ' [RISK]' if entry['is_risk'] else ''
            print(f"\n  {entry['url']}{tag}")
            for ch in entry['changes']:
                print(f"    {ch['dim']} {ch['key']}")
                print(f"      真实: {ch['A']}")
                print(f"      伪装: {ch['B']}")
    else:
        print('\n[diff] 无字段差异（或未捕获到共同请求）')


if __name__ == '__main__':
    main()
