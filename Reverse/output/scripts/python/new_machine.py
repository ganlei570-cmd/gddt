"""
new_machine.py — 一键新机（生成随机 IDFV + 写入设备 + 启动验证）
每次运行生成全新设备身份，写入 /var/mobile/Documents/amap_profiles/active.json
然后以 bypass+spoof 模式启动高德，供手动验收测试

用法:
    python new_machine.py            # 生成新身份并启动高德（保持 120 秒）
    python new_machine.py --show     # 只打印当前 active.json，不启动
"""

import frida, json, uuid, sys, io, time, argparse
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

DEVICE_ID    = 'fcb0b05ae20229767149e98cb3ac94dcde52f74f'
BUNDLE_ID    = 'com.autonavi.amap'
DEVICE_PATH  = '/var/mobile/Documents/amap_profiles/active.json'
SCRIPT_DIR   = Path(__file__).parent.parent / 'frida'
PROFILES_DIR = Path(__file__).parent.parent / 'profiles'
HOLD_SECS    = 120


def gen_profile() -> dict:
    return {
        "idfv": str(uuid.uuid4()).upper(),
        "idfa": "00000000-0000-0000-0000-000000000000",
        "keychain": {
            "com.autonavi.amap/udid":          "CLEAR",
            "com.autonavi.amap/vimsi":         "CLEAR",
            "com.autonavi.amap/vimei":         "CLEAR",
            "com.autonavi.amap/tid":           "CLEAR",
            "com.autonavi.amap/public_key":    "CLEAR",
            "gd_amap/gd_amap":                "CLEAR",
            "com.amap.adiu.key/com.amap.adiu.key": "CLEAR",
            "0.umid_v1/com.autonavi.amap":    "CLEAR",
            "PNS_UniqueId_com.autonavi.amap/PNS_UniqueId_com.autonavi.amap": "CLEAR"
        },
        "userdefaults": {
            "__AMAP_APP_FIRST__":             None,
            "appInitMd5":                     None,
            "login_credit":                   None,
            "ATAuthSDK_POP_com.autonavi.amap": None
        }
    }


# ── 写入设备 active.json（通过 Frida 注入 C fopen/fputs）────────────────
_WRITE_JS = r"""
(function(path, content) {
    var mkdir  = new NativeFunction(Module.findExportByName(null, 'mkdir'),  'int',     ['pointer', 'int']);
    var fopen  = new NativeFunction(Module.findExportByName(null, 'fopen'),  'pointer', ['pointer', 'pointer']);
    var fputs  = new NativeFunction(Module.findExportByName(null, 'fputs'),  'int',     ['pointer', 'pointer']);
    var fclose = new NativeFunction(Module.findExportByName(null, 'fclose'), 'int',     ['pointer']);

    mkdir(Memory.allocUtf8String('/var/mobile/Documents/amap_profiles'), 0x1ed);
    var fp = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('w'));
    if (fp.isNull()) { send({ok: false, msg: 'fopen failed'}); return; }
    fputs(Memory.allocUtf8String(content), fp);
    fclose(fp);
    send({ok: true});
})(__PATH__, __CONTENT__);
"""


def write_profile_to_device(dev: frida.core.Device, profile: dict) -> None:
    content = json.dumps(profile, ensure_ascii=False, indent=2)
    js = _WRITE_JS \
        .replace('__PATH__',    json.dumps(DEVICE_PATH)) \
        .replace('__CONTENT__', json.dumps(content))

    pid = dev.spawn([BUNDLE_ID])
    session = dev.attach(pid)
    done, err = [False], [None]

    def on_msg(msg, _):
        p = msg.get('payload', {})
        if isinstance(p, dict):
            done[0] = p.get('ok', False)
            err[0]  = p.get('msg')

    s = session.create_script(js)
    s.on('message', on_msg)
    s.load()
    time.sleep(1)
    try: session.detach()
    except: pass
    try: dev.kill(pid)
    except: pass

    if err[0]:
        raise RuntimeError(f'写入失败: {err[0]}')
    if not done[0]:
        raise RuntimeError('写入超时或未收到确认')
    print(f'[new_machine] ✅ active.json 写入成功')


# ── 启动 App 并持续保活（供手动测试）───────────────────────────────────
def launch_and_hold(dev: frida.core.Device, idfv: str) -> None:
    bypass  = (SCRIPT_DIR / 'bypass.js').read_text(encoding='utf-8')
    spoof   = (SCRIPT_DIR / 'spoof.js').read_text(encoding='utf-8')
    combined = bypass + '\n\n' + spoof

    pid = dev.spawn([BUNDLE_ID])
    session = dev.attach(pid)
    detached = [False]
    session.on('detached', lambda r, c: detached.__setitem__(0, True))

    def on_msg(msg, _):
        p = msg.get('payload', {})
        if isinstance(p, dict) and p.get('type') == 'idfv':
            actual = p.get('value', '')
            ok = '✅' if actual.upper() == idfv.upper() else '⚠️'
            print(f'  {ok} IDFV 实测: {actual}')

    s = session.create_script(combined)
    s.on('message', on_msg)
    s.load()
    dev.resume(pid)

    print(f'[new_machine] App 已启动，保持 {HOLD_SECS} 秒供手动验收...')
    print(f'[new_machine] 验收项: ①搜索商家看团购 ②注册新手机号 ③搜索地点不掉登录')

    deadline = time.time() + HOLD_SECS
    while time.time() < deadline and not detached[0]:
        time.sleep(2)

    try: session.detach()
    except: pass
    try: dev.kill(pid)
    except: pass


# ── 主入口 ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='一键新机工具')
    parser.add_argument('--show', action='store_true', help='只显示当前 active.json，不启动')
    args = parser.parse_args()

    local = PROFILES_DIR / 'active.json'

    if args.show:
        if local.exists():
            print(json.dumps(json.loads(local.read_text(encoding='utf-8')), indent=2, ensure_ascii=False))
        else:
            print('[new_machine] 尚无 active.json，将使用内置默认值')
        return

    profile = gen_profile()
    idfv    = profile['idfv']
    print(f'[new_machine] 新 IDFV: {idfv}')

    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    local.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'[new_machine] 本地存档: {local}')

    dev = frida.get_device(DEVICE_ID)
    write_profile_to_device(dev, profile)

    dev = frida.get_device(DEVICE_ID)
    launch_and_hold(dev, idfv)

    print(f'\n[new_machine] 完成 — 本次身份: IDFV={idfv}')
    print('[new_machine] 下次运行 new_machine.py 会再生成全新身份')


if __name__ == '__main__':
    main()
