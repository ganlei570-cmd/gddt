"""
backup.py — 高德地图设备指纹 + 登录态备份
用法：
    python backup.py                       # 只备份设备指纹
    python backup.py --login               # 备份设备指纹 + 登录态 (Cookies/Keychain-auth)
    python backup.py --login --name saved  # 指定档案名
    python backup.py --login --as-active   # 同时写 active.json（新机伪装用）
"""

import frida
import sys
import json
import time
import argparse
import io
from pathlib import Path
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

DEVICE_ID  = 'fcb0b05ae20229767149e98cb3ac94dcde52f74f'
BUNDLE_ID  = 'com.autonavi.amap'
BYPASS_JS  = Path(__file__).parent.parent / 'frida' / 'bypass.js'
PROFILES   = Path(__file__).parent.parent.parent / 'profiles'

# ── 设备指纹 Keychain 条目 ────────────────────────
FINGERPRINT_KEYCHAIN = [
    ('com.autonavi.amap', 'udid'),
    ('com.autonavi.amap', 'vimsi'),
    ('com.autonavi.amap', 'vimei'),
    ('com.autonavi.amap', 'tid'),
    ('com.autonavi.amap', 'public_key'),
    ('gd_amap',           'gd_amap'),
    ('com.amap.adiu.key', 'com.amap.adiu.key'),
    ('0.umid_v1',         'com.autonavi.amap'),
    ('PNS_UniqueId_com.autonavi.amap', 'PNS_UniqueId_com.autonavi.amap'),
]

UD_TARGETS = [
    '__AMAP_APP_FIRST__',
    'appInitMd5',
    'login_credit',
    'ATAuthSDK_POP_com.autonavi.amap',
]

# Cookie 域名过滤（只备份高德相关 cookie）
COOKIE_DOMAINS = ['.amap.com', '.autonavi.com', 'amap.com', 'autonavi.com',
                  '.alipay.com', '.taobao.com']

DUMP_SCRIPT = r"""
'use strict';

var SEC_kSecClass                = Memory.readPointer(Module.findExportByName('Security', 'kSecClass'));
var SEC_kSecAttrService          = Memory.readPointer(Module.findExportByName('Security', 'kSecAttrService'));
var SEC_kSecAttrAccount          = Memory.readPointer(Module.findExportByName('Security', 'kSecAttrAccount'));
var SEC_kSecClassGenericPassword = Memory.readPointer(Module.findExportByName('Security', 'kSecClassGenericPassword'));
var SEC_kSecReturnData           = Memory.readPointer(Module.findExportByName('Security', 'kSecReturnData'));
var SEC_kSecReturnAttributes     = Memory.readPointer(Module.findExportByName('Security', 'kSecReturnAttributes'));
var SEC_kSecMatchLimit           = Memory.readPointer(Module.findExportByName('Security', 'kSecMatchLimit'));
var SEC_kSecMatchLimitOne        = Memory.readPointer(Module.findExportByName('Security', 'kSecMatchLimitOne'));
var SEC_kSecMatchLimitAll        = Memory.readPointer(Module.findExportByName('Security', 'kSecMatchLimitAll'));

var SecItemCopyMatchingFn = new NativeFunction(
    Module.findExportByName('Security', 'SecItemCopyMatching'),
    'int', ['pointer', 'pointer']
);

function keychainGet(service, account) {
    var q = ObjC.classes.NSMutableDictionary.dictionary();
    q.setObject_forKey_(SEC_kSecClassGenericPassword, SEC_kSecClass);
    q.setObject_forKey_(ObjC.classes.NSString.stringWithString_(service),  SEC_kSecAttrService);
    q.setObject_forKey_(ObjC.classes.NSString.stringWithString_(account),  SEC_kSecAttrAccount);
    q.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(1), SEC_kSecReturnData);
    q.setObject_forKey_(SEC_kSecMatchLimitOne, SEC_kSecMatchLimit);
    var out = Memory.alloc(Process.pointerSize);
    Memory.writePointer(out, ptr(0));
    if (SecItemCopyMatchingFn(q.handle, out) !== 0) return null;
    var ptr0 = Memory.readPointer(out);
    if (ptr0.isNull()) return null;
    var data = new ObjC.Object(ptr0);
    try {
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
        return s ? s.toString() : data.base64EncodedStringWithOptions_(0).toString();
    } catch(e) {
        return data.base64EncodedStringWithOptions_(0).toString();
    }
}

function keychainScanAll() {
    // 扫描所有 GenericPassword 条目（用于发现登录 token）
    var q = ObjC.classes.NSMutableDictionary.dictionary();
    q.setObject_forKey_(SEC_kSecClassGenericPassword,              SEC_kSecClass);
    q.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(1),  SEC_kSecReturnData);
    q.setObject_forKey_(ObjC.classes.NSNumber.numberWithBool_(1),  SEC_kSecReturnAttributes);
    q.setObject_forKey_(SEC_kSecMatchLimitAll,                     SEC_kSecMatchLimit);
    var out = Memory.alloc(Process.pointerSize);
    Memory.writePointer(out, ptr(0));
    if (SecItemCopyMatchingFn(q.handle, out) !== 0) return [];
    var ptr0 = Memory.readPointer(out);
    if (ptr0.isNull()) return [];
    var arr = new ObjC.Object(ptr0);
    var count = arr.count().valueOf();
    var results = [];
    for (var i = 0; i < count; i++) {
        try {
            var item    = arr.objectAtIndex_(i);
            var svc     = item.objectForKey_(SEC_kSecAttrService);
            var acc     = item.objectForKey_(SEC_kSecAttrAccount);
            var dataRaw = item.objectForKey_(SEC_kSecValueData);
            var svcStr  = svc ? svc.toString() : '';
            var accStr  = acc ? acc.toString() : '';
            var dataStr = '';
            if (dataRaw && !dataRaw.handle.isNull()) {
                try {
                    var ds = ObjC.classes.NSString.alloc().initWithData_encoding_(dataRaw, 4);
                    dataStr = ds ? ds.toString() : dataRaw.base64EncodedStringWithOptions_(0).toString();
                } catch(e) {
                    dataStr = dataRaw.base64EncodedStringWithOptions_(0).toString();
                }
            }
            results.push({ service: svcStr, account: accStr, data: dataStr });
        } catch(e) {}
    }
    return results;
}

function udGet(key) {
    var ud = ObjC.classes.NSUserDefaults.standardUserDefaults();
    var val = ud.objectForKey_(key);
    if (!val || val.handle.equals(ptr(0))) return null;
    try { return val.toString(); } catch(e) { return null; }
}

function cookieDump(domainFilter) {
    var storage = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage();
    var cookies = storage.cookies();
    var count   = cookies.count().valueOf();
    var result  = [];
    for (var i = 0; i < count; i++) {
        try {
            var c      = cookies.objectAtIndex_(i);
            var domain = c.domain().toString();
            var keep   = false;
            for (var j = 0; j < domainFilter.length; j++) {
                if (domain.indexOf(domainFilter[j]) >= 0) { keep = true; break; }
            }
            if (!keep) continue;
            result.push({
                name:    c.name().toString(),
                value:   c.value().toString(),
                domain:  domain,
                path:    c.path().toString(),
                secure:  c.isSecure() ? true : false,
                expires: c.expiresDate() ? c.expiresDate().timeIntervalSince1970() : null,
            });
        } catch(e) {}
    }
    return result;
}

// ── IDFV ──
var idfv = null;
try {
    idfv = ObjC.classes.UIDevice.currentDevice().identifierForVendor().UUIDString().toString();
} catch(e) {}

// ── 设备指纹 Keychain ──
var FINGERPRINT_KEYCHAIN = %s;
var keychain = {};
for (var i = 0; i < FINGERPRINT_KEYCHAIN.length; i++) {
    var t = FINGERPRINT_KEYCHAIN[i];
    keychain[t[0] + '/' + t[1]] = keychainGet(t[0], t[1]);
}

// ── NSUserDefaults ──
var UD_TARGETS = %s;
var userdefaults = {};
for (var j = 0; j < UD_TARGETS.length; j++) {
    userdefaults[UD_TARGETS[j]] = udGet(UD_TARGETS[j]);
}

// ── 登录态（可选）──
var includeLogin = %s;
var loginData = null;
if (includeLogin) {
    var COOKIE_DOMAINS = %s;
    loginData = {
        cookies:           cookieDump(COOKIE_DOMAINS),
        keychain_all:      keychainScanAll(),
    };
}

send({ type: 'dump', idfv: idfv, keychain: keychain, userdefaults: userdefaults, login: loginData });
"""

# ── 登录态 Keychain 过滤（只保留高德/认证相关）─────────
LOGIN_KEYCHAIN_KEYWORDS = [
    'autonavi', 'amap', 'token', 'login', 'auth', 'session',
    'uid', 'user', 'credit', 'ticket', 'sso', 'alipay',
]

def is_login_keychain(item: dict) -> bool:
    svc = item.get('service', '').lower()
    acc = item.get('account', '').lower()
    for kw in LOGIN_KEYCHAIN_KEYWORDS:
        if kw in svc or kw in acc:
            return True
    return False


def run_dump(dev, include_login: bool) -> dict:
    pid     = dev.spawn([BUNDLE_ID])
    session = dev.attach(pid)

    bypass = BYPASS_JS.read_text(encoding='utf-8')
    sb = session.create_script(bypass)
    sb.on('message', lambda m, d: None)
    sb.load()

    code = DUMP_SCRIPT % (
        json.dumps(FINGERPRINT_KEYCHAIN),
        json.dumps(UD_TARGETS),
        'true' if include_login else 'false',
        json.dumps(COOKIE_DOMAINS),
    )
    result = {}

    def on_msg(msg, _data):
        if msg.get('type') == 'send' and isinstance(msg.get('payload'), dict):
            if msg['payload'].get('type') == 'dump':
                result.update(msg['payload'])

    sd = session.create_script(code)
    sd.on('message', on_msg)
    sd.load()
    dev.resume(pid)

    deadline = time.time() + 30
    while 'idfv' not in result and time.time() < deadline:
        time.sleep(0.5)

    session.detach()
    return result


def build_profile(result: dict, include_login: bool) -> dict:
    profile = {
        '_version': '1.0',
        '_created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        '_source':  'backup',
        'idfv':         result.get('idfv'),
        'idfa':         '00000000-0000-0000-0000-000000000000',
        'keychain':     result.get('keychain', {}),
        'userdefaults': result.get('userdefaults', {}),
    }
    if include_login and result.get('login'):
        raw_kc = result['login'].get('keychain_all', [])
        profile['login'] = {
            'cookies':  result['login'].get('cookies', []),
            'keychain': [item for item in raw_kc if is_login_keychain(item)],
        }
    return profile


def print_summary(profile: dict) -> None:
    print(f'  IDFV: {profile.get("idfv")}')
    for k, v in profile.get('keychain', {}).items():
        short = (str(v or ''))[:24] + '...' if v and len(str(v)) > 24 else v
        print(f'  KC [{k}]: {short}')
    if 'login' in profile:
        cookies = profile['login'].get('cookies', [])
        kc_auth = profile['login'].get('keychain', [])
        print(f'  Cookies: {len(cookies)} 条')
        print(f'  Auth Keychain: {len(kc_auth)} 条')
        for item in kc_auth:
            short = str(item.get('data', ''))[:24] + '...'
            print(f'    KC-AUTH [{item["service"]}/{item["account"]}]: {short}')


def main() -> None:
    parser = argparse.ArgumentParser(description='高德地图设备指纹 + 登录态备份')
    parser.add_argument('--login',     action='store_true', help='同时备份登录态 (Cookies + Keychain-auth)')
    parser.add_argument('--name',      default=None,        help='档案名称（无扩展名）')
    parser.add_argument('--as-active', action='store_true', help='同时写 active.json')
    args = parser.parse_args()

    PROFILES.mkdir(parents=True, exist_ok=True)

    print('[backup] 连接设备...')
    dev    = frida.get_device(DEVICE_ID)
    result = run_dump(dev, args.login)

    if 'idfv' not in result:
        print('[ERROR] dump 超时')
        sys.exit(1)

    profile   = build_profile(result, args.login)
    name      = args.name or 'backup_' + datetime.now().strftime('%Y%m%d_%H%M%S')
    out_path  = PROFILES / f'{name}.json'
    out_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'[backup] 已保存: {out_path}')

    if args.as_active:
        (PROFILES / 'active.json').write_text(
            json.dumps(profile, indent=2, ensure_ascii=False), encoding='utf-8'
        )
        print('[backup] active.json 已更新')

    print('[backup] 备份完成:')
    print_summary(profile)


if __name__ == '__main__':
    main()
