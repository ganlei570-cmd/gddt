"""
restore.py — 高德地图设备指纹 + 登录态还原
用法：
    python restore.py                           # 列出所有档案
    python restore.py --profile my_profile      # 激活指定档案（设备指纹）
    python restore.py --profile my_profile --login  # 同时还原登录态 (Cookie + Keychain-auth)
    python restore.py --new-device              # 激活内置新机档案（清空登录态）
"""

import frida
import sys
import json
import time
import argparse
import io
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

DEVICE_ID  = 'fcb0b05ae20229767149e98cb3ac94dcde52f74f'
BUNDLE_ID  = 'com.autonavi.amap'
BYPASS_JS  = Path(__file__).parent.parent / 'frida' / 'bypass.js'
PROFILES   = Path(__file__).parent.parent.parent / 'profiles'
REMOTE_DIR = '/var/mobile/Documents/amap_profiles'

# ── 推 active.json 到手机 ──────────────────────────
PUSH_SCRIPT = r"""
'use strict';
recv(function(payload) {
    if (payload.type !== 'push') return;
    try {
        var fm  = ObjC.classes.NSFileManager.defaultManager();
        var dir = payload.path.substring(0, payload.path.lastIndexOf('/'));
        fm.createDirectoryAtPath_withIntermediateDirectories_attributes_error_(dir, 1, null, null);
        ObjC.classes.NSString.stringWithString_(payload.content)
            .writeToFile_atomically_encoding_error_(payload.path, 1, 4, null);
        send({ ok: true });
    } catch(e) {
        send({ ok: false, error: '' + e });
    }
});
send({ ready: true });
"""

# ── 注入 Cookie + 写入认证 Keychain ──────────────
RESTORE_LOGIN_SCRIPT = r"""
'use strict';

var SEC_kSecClass                = Memory.readPointer(Module.findExportByName('Security', 'kSecClass'));
var SEC_kSecAttrService          = Memory.readPointer(Module.findExportByName('Security', 'kSecAttrService'));
var SEC_kSecAttrAccount          = Memory.readPointer(Module.findExportByName('Security', 'kSecAttrAccount'));
var SEC_kSecClassGenericPassword = Memory.readPointer(Module.findExportByName('Security', 'kSecClassGenericPassword'));
var SEC_kSecValueData            = Memory.readPointer(Module.findExportByName('Security', 'kSecValueData'));
var SEC_kSecAttrAccessible       = Memory.readPointer(Module.findExportByName('Security', 'kSecAttrAccessible'));
var SEC_kSecAttrAccessibleAfterFirstUnlock = Memory.readPointer(
    Module.findExportByName('Security', 'kSecAttrAccessibleAfterFirstUnlock')
);

var SecItemAddFn    = new NativeFunction(Module.findExportByName('Security', 'SecItemAdd'),    'int', ['pointer', 'pointer']);
var SecItemDeleteFn = new NativeFunction(Module.findExportByName('Security', 'SecItemDelete'), 'int', ['pointer']);

function keychainSet(service, account, value) {
    // 先删再写，避免 duplicate 错误
    var del = ObjC.classes.NSMutableDictionary.dictionary();
    del.setObject_forKey_(SEC_kSecClassGenericPassword, SEC_kSecClass);
    del.setObject_forKey_(ObjC.classes.NSString.stringWithString_(service),  SEC_kSecAttrService);
    del.setObject_forKey_(ObjC.classes.NSString.stringWithString_(account),  SEC_kSecAttrAccount);
    SecItemDeleteFn(del.handle);

    var data = ObjC.classes.NSString.stringWithString_(value).dataUsingEncoding_(4);
    var add  = ObjC.classes.NSMutableDictionary.dictionary();
    add.setObject_forKey_(SEC_kSecClassGenericPassword,            SEC_kSecClass);
    add.setObject_forKey_(ObjC.classes.NSString.stringWithString_(service),  SEC_kSecAttrService);
    add.setObject_forKey_(ObjC.classes.NSString.stringWithString_(account),  SEC_kSecAttrAccount);
    add.setObject_forKey_(data,                                    SEC_kSecValueData);
    add.setObject_forKey_(SEC_kSecAttrAccessibleAfterFirstUnlock,  SEC_kSecAttrAccessible);
    var status = SecItemAddFn(add.handle, null);
    return status === 0;
}

function cookieRestore(cookieList) {
    var storage = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage();
    // 先清除高德相关域的旧 cookie
    var existing = storage.cookies();
    var count = existing.count().valueOf();
    var toDelete = [];
    for (var i = 0; i < count; i++) {
        var c = existing.objectAtIndex_(i);
        var d = c.domain().toString();
        if (d.indexOf('amap') >= 0 || d.indexOf('autonavi') >= 0 || d.indexOf('alipay') >= 0) {
            toDelete.push(c);
        }
    }
    for (var j = 0; j < toDelete.length; j++) {
        storage.deleteCookie_(toDelete[j]);
    }

    // 写入备份的 cookie
    for (var k = 0; k < cookieList.length; k++) {
        try {
            var info = cookieList[k];
            var props = ObjC.classes.NSMutableDictionary.dictionary();
            props.setObject_forKey_(
                ObjC.classes.NSString.stringWithString_(info.name),
                ObjC.classes.NSString.stringWithString_('Name')
            );
            props.setObject_forKey_(
                ObjC.classes.NSString.stringWithString_(info.value),
                ObjC.classes.NSString.stringWithString_('Value')
            );
            props.setObject_forKey_(
                ObjC.classes.NSString.stringWithString_(info.domain),
                ObjC.classes.NSString.stringWithString_('Domain')
            );
            props.setObject_forKey_(
                ObjC.classes.NSString.stringWithString_(info.path || '/'),
                ObjC.classes.NSString.stringWithString_('Path')
            );
            var cookie = ObjC.classes.NSHTTPCookie.cookieWithProperties_(props);
            if (cookie && !cookie.handle.isNull()) {
                storage.setCookie_(cookie);
            }
        } catch(e) {}
    }
    return cookieList.length;
}

recv(function(payload) {
    if (payload.type !== 'restore_login') return;

    var kcCount     = 0;
    var cookieCount = 0;

    // 还原认证 Keychain
    var items = payload.keychain || [];
    for (var i = 0; i < items.length; i++) {
        var item = items[i];
        if (item.data && item.service && item.account) {
            if (keychainSet(item.service, item.account, item.data)) kcCount++;
        }
    }

    // 还原 Cookie
    var cookies = payload.cookies || [];
    cookieCount = cookieRestore(cookies);

    send({ ok: true, keychain: kcCount, cookies: cookieCount });
});
send({ ready: true });
"""


def list_profiles() -> None:
    files = sorted(PROFILES.glob('*.json'))
    if not files:
        print('[restore] 没有找到任何档案')
        return
    for f in files:
        try:
            p       = json.loads(f.read_text(encoding='utf-8'))
            created = p.get('_created', '?')
            idfv    = p.get('idfv', '?')
            src     = p.get('_source', '?')
            has_login = 'login' in p
            flag    = ' [+登录态]' if has_login else ''
            print(f'  {f.stem:<30}  {created}  IDFV={idfv}  [{src}]{flag}')
        except Exception:
            print(f'  {f.stem}  (解析失败)')


def push_active(dev: any, pid: int, profile_json: str) -> bool:
    remote_path = f'{REMOTE_DIR}/active.json'
    session     = dev.attach(pid)
    s           = session.create_script(PUSH_SCRIPT)
    state       = {}

    def on_msg(msg, _):
        if msg.get('type') == 'send' and isinstance(msg.get('payload'), dict):
            state.update(msg['payload'])

    s.on('message', on_msg)
    s.load()

    deadline = time.time() + 8
    while 'ready' not in state and time.time() < deadline:
        time.sleep(0.2)

    s.post({'type': 'push', 'content': profile_json, 'path': remote_path})

    deadline = time.time() + 10
    while 'ok' not in state and time.time() < deadline:
        time.sleep(0.2)

    session.detach()
    return state.get('ok', False)


def restore_login(dev: any, pid: int, login_data: dict) -> dict:
    session = dev.attach(pid)
    s       = session.create_script(RESTORE_LOGIN_SCRIPT)
    state   = {}

    def on_msg(msg, _):
        if msg.get('type') == 'send' and isinstance(msg.get('payload'), dict):
            state.update(msg['payload'])

    s.on('message', on_msg)
    s.load()

    deadline = time.time() + 8
    while 'ready' not in state and time.time() < deadline:
        time.sleep(0.2)

    s.post({
        'type':     'restore_login',
        'keychain': login_data.get('keychain', []),
        'cookies':  login_data.get('cookies', []),
    })

    deadline = time.time() + 15
    while 'ok' not in state and time.time() < deadline:
        time.sleep(0.2)

    session.detach()
    return state


def get_running_pid(dev: any) -> int | None:
    try:
        procs = dev.enumerate_processes()
        p = next((p for p in procs if p.name == 'AMapiPhone'), None)
        return p.pid if p else None
    except Exception:
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description='高德地图档案还原')
    parser.add_argument('--list',       action='store_true',  help='列出所有档案')
    parser.add_argument('--profile',    default=None,         help='档案名称（无扩展名）')
    parser.add_argument('--new-device', action='store_true',  help='激活内置新机档案')
    parser.add_argument('--login',      action='store_true',  help='同时还原登录态 (Cookie + Keychain-auth)')
    args = parser.parse_args()

    if args.list or (not args.profile and not args.new_device):
        list_profiles()
        return

    # 确定档案
    if args.new_device:
        src_path = PROFILES / 'new_device.json'
        if not src_path.exists():
            print('[ERROR] profiles/new_device.json 不存在')
            sys.exit(1)
    else:
        src_path = PROFILES / f'{args.profile}.json'
        if not src_path.exists():
            print(f'[ERROR] 找不到档案: {src_path}')
            list_profiles()
            sys.exit(1)

    profile      = json.loads(src_path.read_text(encoding='utf-8'))
    profile_json = json.dumps(profile, indent=2, ensure_ascii=False)

    print('[restore] 连接设备...')
    dev = frida.get_device(DEVICE_ID)

    # 优先 attach 已运行的高德；否则 spawn
    pid = get_running_pid(dev)
    if pid:
        print(f'[restore] attach AMapiPhone (pid={pid})')
    else:
        pid = dev.spawn([BUNDLE_ID])
        print(f'[restore] spawned AMapiPhone (pid={pid})')

        bypass = BYPASS_JS.read_text(encoding='utf-8')
        session = dev.attach(pid)
        sb = session.create_script(bypass)
        sb.on('message', lambda m, d: None)
        sb.load()
        dev.resume(pid)
        session.detach()
        time.sleep(2)

    # 1. 推 active.json（供 spoof.js 读取）
    ok = push_active(dev, pid, profile_json)
    if ok:
        print(f'[restore] active.json -> {REMOTE_DIR}/active.json')
    else:
        print('[WARN] active.json 写入失败（越狱权限？）')

    # 2. 可选：直接注入登录态到运行中的 App
    if args.login:
        login_data = profile.get('login')
        if not login_data:
            print('[WARN] 档案中没有登录态数据，跳过登录还原')
        else:
            result = restore_login(dev, pid, login_data)
            if result.get('ok'):
                print(f'[restore] 登录态还原: Keychain={result.get("keychain")} 条, Cookie={result.get("cookies")} 条')
            else:
                print('[WARN] 登录态还原失败')
    elif 'login' in profile:
        print('[restore] 提示: 档案含登录态，加 --login 参数可一并还原')

    name = 'new_device' if args.new_device else args.profile
    print(f'[restore] 完成: [{name}]  IDFV={profile.get("idfv")}')
    print('[restore] 重启高德并配合 bypass.js + spoof.js 加载后生效')


if __name__ == '__main__':
    main()
