"""
capture.py — mitmproxy 插件：过滤高德 + 风控接口流量
用法：
    mitmdump -p 8080 -s capture.py               # 捕获并实时打印
    mitmdump -p 8080 -s capture.py --set name=A  # 保存到 samples/capture_A.json
    mitmdump -p 8080 -s capture.py --set name=B  # 保存到 samples/capture_B.json

手机设置代理：
    WiFi -> 代理 -> 手动 -> 服务器: <PC 局域网 IP> 端口: 8080
    首次连接：访问 http://mitm.it 安装 mitmproxy CA 证书（需在设置->证书->信任）

捕获完成后：
    python diff_captures.py samples/capture_A.json samples/capture_B.json
"""

from mitmproxy import http, ctx
from pathlib import Path
from datetime import datetime
import json
import re

# 只捕获这些域名（高德 + 阿里风控）
CAPTURE_DOMAINS = [
    'amap.com',
    'autonavi.com',
    'ynuf.aliapp.org',      # Alibaba 风控上报（UMID / DTHbalSe）
    'ynuf.alipay.com',
    'amdc.m.taobao.com',
    'tb.cn',
    'log.mmstat.com',       # 阿里日志统计
    'security.alibaba.com',
]

# 关键词（含这些词的请求优先关注）
RISK_KEYWORDS = [
    'risk', 'device', 'fingerprint', 'umid', 'udid', 'imei', 'imsi',
    'did', 'token', 'report', 'collect', 'shield', 'dthl', 'dth',
    'security', 'check', 'verify', 'appmonitor', 'um.json',
]

SAMPLES_DIR = Path(__file__).parent.parent.parent / 'samples'


def _domain_match(host: str) -> bool:
    for d in CAPTURE_DOMAINS:
        if host == d or host.endswith('.' + d):
            return True
    return False


def _is_risk_request(flow: http.HTTPFlow) -> bool:
    url = flow.request.pretty_url.lower()
    path_qs = (flow.request.path + flow.request.get_text()).lower()
    for kw in RISK_KEYWORDS:
        if kw in url or kw in path_qs:
            return True
    return False


def _safe_body(flow_message) -> str:
    try:
        ct = flow_message.headers.get('content-type', '')
        if 'json' in ct or 'text' in ct or 'form' in ct:
            return flow_message.get_text(strict=False) or ''
        data = flow_message.content or b''
        if len(data) < 4096:
            return data.hex()
        return '[binary ' + str(len(data)) + ' bytes]'
    except Exception:
        return '[error reading body]'


class AmapCapture:
    def __init__(self):
        self._flows: list[dict] = []
        self._out_name: str = ''

    def load(self, loader):
        loader.add_option('name', str, '', 'Capture name for output file')

    def configure(self, updates):
        if 'name' in updates:
            self._out_name = ctx.options.name

    def request(self, flow: http.HTTPFlow) -> None:
        if not _domain_match(flow.request.host):
            return
        flow.metadata['captured'] = True
        flow.metadata['is_risk']  = _is_risk_request(flow)

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.metadata.get('captured'):
            return

        entry = {
            'ts':      datetime.now().isoformat(),
            'is_risk': flow.metadata.get('is_risk', False),
            'request': {
                'method':  flow.request.method,
                'url':     flow.request.pretty_url,
                'headers': dict(flow.request.headers),
                'body':    _safe_body(flow.request),
            },
            'response': {
                'status':  flow.response.status_code,
                'headers': dict(flow.response.headers),
                'body':    _safe_body(flow.response),
            },
        }
        self._flows.append(entry)

        # 实时打印风控请求
        if flow.metadata.get('is_risk'):
            tag = '[RISK]'
        else:
            tag = '[AMAP]'
        print(f'{tag} {flow.request.method} {flow.request.pretty_url[:80]} -> {flow.response.status_code}')

        # 自动存档
        if self._out_name:
            self._save()

    def _save(self) -> None:
        SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
        out = SAMPLES_DIR / f'capture_{self._out_name}.json'
        out.write_text(
            json.dumps({'flows': self._flows}, indent=2, ensure_ascii=False),
            encoding='utf-8'
        )

    def done(self) -> None:
        if not self._flows:
            return
        name = self._out_name or datetime.now().strftime('%Y%m%d_%H%M%S')
        SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
        out = SAMPLES_DIR / f'capture_{name}.json'
        out.write_text(
            json.dumps({'flows': self._flows}, indent=2, ensure_ascii=False),
            encoding='utf-8'
        )
        risk_count = sum(1 for f in self._flows if f['is_risk'])
        print(f'[capture] 保存 {len(self._flows)} 条请求 (风控相关: {risk_count}) -> {out}')


addons = [AmapCapture()]
