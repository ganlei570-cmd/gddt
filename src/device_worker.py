import frida, json, uuid, time, shutil
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import QThread, Signal

DEVICE_ID    = 'fcb0b05ae20229767149e98cb3ac94dcde52f74f'
BUNDLE_ID    = 'com.autonavi.amap'
DEVICE_PATH  = '/var/mobile/Documents/amap_profiles/active.json'
_ROOT        = Path(__file__).parent.parent
PROFILES_DIR = _ROOT / 'Reverse' / 'output' / 'profiles'
SCRIPT_DIR   = _ROOT / 'Reverse' / 'output' / 'scripts' / 'frida'

_WRITE_JS = r"""(function(path, content) {
    var mk = new NativeFunction(Module.findExportByName(null,'mkdir'),'int',['pointer','int']);
    var fo = new NativeFunction(Module.findExportByName(null,'fopen'),'pointer',['pointer','pointer']);
    var fp = new NativeFunction(Module.findExportByName(null,'fputs'),'int',['pointer','pointer']);
    var fc = new NativeFunction(Module.findExportByName(null,'fclose'),'int',['pointer']);
    mk(Memory.allocUtf8String('/var/mobile/Documents/amap_profiles'),0x1ed);
    var f = fo(Memory.allocUtf8String(path),Memory.allocUtf8String('w'));
    if(f.isNull()){send({ok:false,msg:'fopen failed'});return;}
    fp(Memory.allocUtf8String(content),f); fc(f); send({ok:true});
})(__PATH__, __CONTENT__);"""

_INFO_JS = r"""(function(){
    try {
        var d = ObjC.classes.UIDevice.currentDevice();
        send({
            model:  String(d.model()),
            sysver: String(d.systemVersion()),
            idfv:   String(d.identifierForVendor().UUIDString()),
            name:   String(d.name())
        });
    } catch(e) { send({error: String(e)}); }
})();"""

_KC_CLEAR_JS = r"""(function(keys){
    try {
        ObjC.classes.NSObject;
        var SecItemDelete = new NativeFunction(
            Module.findExportByName('Security','SecItemDelete'),'int',['pointer']);
        function _ptr(n){
            var a=Module.findExportByName('Security',n);
            return a ? ptr(a).readPointer() : ptr(0);
        }
        var kSecClass = _ptr('kSecClass');
        var kSecClassGenericPassword = _ptr('kSecClassGenericPassword');
        var kSecAttrService = _ptr('kSecAttrService');
        var kSecAttrAccount = _ptr('kSecAttrAccount');
        var NSS = ObjC.classes.NSString;
        var NSD = ObjC.classes.NSMutableDictionary;
        keys.forEach(function(k){
            var parts = k.split('/');
            var q = NSD.alloc().init();
            q.setObject_forKey_(ObjC.Object(kSecClassGenericPassword), ObjC.Object(kSecClass));
            q.setObject_forKey_(NSS.stringWithString_(parts[0]), ObjC.Object(kSecAttrService));
            q.setObject_forKey_(NSS.stringWithString_(parts[1]||parts[0]), ObjC.Object(kSecAttrAccount));
            SecItemDelete(q);
        });
        send({ok:true});
    } catch(e){ send({ok:false,msg:String(e)}); }
})(__KC_KEYS__);"""

_KC_KEYS = [
    'com.autonavi.amap/udid', 'com.autonavi.amap/vimsi', 'com.autonavi.amap/vimei',
    'com.autonavi.amap/tid', 'com.autonavi.amap/public_key', 'gd_amap/gd_amap',
    'com.amap.adiu.key/com.amap.adiu.key', '0.umid_v1/com.autonavi.amap',
    'PNS_UniqueId_com.autonavi.amap/PNS_UniqueId_com.autonavi.amap'
]


def gen_profile(idfv: str = None) -> dict:
    return {
        'idfv': idfv or str(uuid.uuid4()).upper(),
        'idfa': '00000000-0000-0000-0000-000000000000',
        'keychain': {k: 'CLEAR' for k in _KC_KEYS},
        'userdefaults': {
            '__AMAP_APP_FIRST__': None, 'appInitMd5': None,
            'login_credit': None, 'ATAuthSDK_POP_com.autonavi.amap': None
        }
    }


def load_backups() -> list:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for p in sorted(PROFILES_DIR.glob('高德地图_*.json')):
        try:
            data = json.loads(p.read_text(encoding='utf-8'))
            st = p.stat()
            items.append({
                'path': p, 'name': p.stem, 'idfv': data.get('idfv', ''),
                'mtime': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M'),
                'size': st.st_size
            })
        except Exception:
            pass
    return items


def next_backup_name() -> str:
    nums = []
    for p in PROFILES_DIR.glob('高德地图_*.json'):
        try: nums.append(int(p.stem.rsplit('_', 1)[-1]))
        except ValueError: pass
    return f'高德地图_{(max(nums) + 1 if nums else 1):05d}'


class DeviceWorker(QThread):
    device_info    = Signal(dict)
    operation_done = Signal(bool, str)
    log_message    = Signal(str)

    def __init__(self, op: str, **kwargs):
        super().__init__()
        self.op, self.kwargs = op, kwargs

    def run(self):
        dispatch = {
            'connect':        self._connect,
            'new_machine':    self._new_machine,
            'backup':         self._backup,
            'clear_keychain': self._clear_keychain,
            'restore':        self._restore,
        }
        try:
            dispatch[self.op](**self.kwargs)
        except Exception as e:
            self.operation_done.emit(False, str(e))

    def _device(self):
        return frida.get_device(DEVICE_ID)

    def _write_profile(self, dev, profile: dict):
        content = json.dumps(profile, ensure_ascii=False)
        js = (_WRITE_JS
              .replace('__PATH__', json.dumps(DEVICE_PATH))
              .replace('__CONTENT__', json.dumps(content)))
        pid = dev.spawn([BUNDLE_ID])
        ses = dev.attach(pid)
        result = [None]
        s = ses.create_script(js)
        s.on('message', lambda m, _: result.__setitem__(0, m.get('payload', {})))
        s.load()
        time.sleep(1)
        try: ses.detach()
        except: pass
        try: dev.kill(pid)
        except: pass
        if result[0] and not result[0].get('ok'):
            raise RuntimeError(result[0].get('msg', '写入失败'))

    def _connect(self):
        self.log_message.emit('正在连接设备...')
        dev = self._device()
        pid = dev.spawn([BUNDLE_ID])
        ses = dev.attach(pid)
        result = [None]
        s = ses.create_script(_INFO_JS)
        s.on('message', lambda m, _: result.__setitem__(0, m.get('payload')))
        s.load()
        time.sleep(1)
        try: ses.detach()
        except: pass
        try: dev.kill(pid)
        except: pass
        if result[0] and 'model' in result[0]:
            self.device_info.emit(result[0])
        self.operation_done.emit(True, '设备连接成功')

    def _new_machine(self):
        self.log_message.emit('生成新设备身份...')
        profile = gen_profile()
        idfv = profile['idfv']
        self.log_message.emit(f'新 IDFV: {idfv}')
        PROFILES_DIR.mkdir(parents=True, exist_ok=True)
        (PROFILES_DIR / 'active.json').write_text(
            json.dumps(profile, indent=2, ensure_ascii=False), encoding='utf-8')
        dev = self._device()
        self._write_profile(dev, profile)
        self.log_message.emit('active.json 写入成功，启动应用...')
        bypass = (SCRIPT_DIR / 'bypass.js').read_text(encoding='utf-8')
        spoof  = (SCRIPT_DIR / 'spoof.js').read_text(encoding='utf-8')
        pid = dev.spawn([BUNDLE_ID])
        ses = dev.attach(pid)
        s = ses.create_script(bypass + '\n\n' + spoof)
        s.on('message', lambda m, _: self.log_message.emit(str(m.get('payload', ''))))
        s.load()
        dev.resume(pid)
        self.operation_done.emit(True, f'一键新机完成\nIDFV: {idfv}')

    def _backup(self):
        self.log_message.emit('保存当前备份...')
        active = PROFILES_DIR / 'active.json'
        if not active.exists():
            raise RuntimeError('尚无 active.json，请先执行一键新机')
        name = next_backup_name()
        shutil.copy2(active, PROFILES_DIR / f'{name}.json')
        self.operation_done.emit(True, f'备份成功: {name}')

    def _clear_keychain(self):
        self.log_message.emit('清理 Keychain...')
        dev = self._device()
        bypass = (SCRIPT_DIR / 'bypass.js').read_text(encoding='utf-8')
        kc_js  = _KC_CLEAR_JS.replace('__KC_KEYS__', json.dumps(_KC_KEYS))
        pid = dev.spawn([BUNDLE_ID])
        ses = dev.attach(pid)
        s1 = ses.create_script(bypass)
        s1.on('message', lambda m, _: None)
        s1.load()
        dev.resume(pid)
        time.sleep(2)
        result = [False]
        s2 = ses.create_script(kc_js)
        s2.on('message', lambda m, _: result.__setitem__(0, m.get('payload', {}).get('ok', False)))
        s2.load()
        time.sleep(1)
        try: ses.detach()
        except: pass
        try: dev.kill(pid)
        except: pass
        self.operation_done.emit(True, 'Keychain 已清理')

    def _restore(self, backup_path: str = ''):
        if not backup_path:
            raise RuntimeError('未指定备份文件')
        p = Path(backup_path)
        self.log_message.emit(f'还原: {p.stem}')
        profile = json.loads(p.read_text(encoding='utf-8'))
        shutil.copy2(p, PROFILES_DIR / 'active.json')
        dev = self._device()
        self._write_profile(dev, profile)
        self.operation_done.emit(True, f'还原成功: {p.stem}')
