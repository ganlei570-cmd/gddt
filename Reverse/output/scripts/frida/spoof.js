// spoof.js — 高德地图一键新机：设备身份伪装
// 依赖：bypass.js 必须在本脚本之前加载
// 加载顺序：-l bypass.js -l spoof.js（同一 spawn 会话）
// 档案路径：/var/mobile/Documents/amap_profiles/active.json
// 档案不存在时回落 profiles/new_device.json 内置默认值

'use strict';

// ══════════════════════════════════════════════════
// 内置档案（档案文件不存在时的 fallback）
// ══════════════════════════════════════════════════

// Keychain 全部 CLEAR：让 app 以为是全新设备，基于伪造 IDFV 重新生成所有标识符。
// 注意：这些条目存储的是二进制 UUID（16 字节），不是字符串，
// 注入错误格式的字符串会导致 app 崩溃，所以统一用 CLEAR。
var BUILTIN_PROFILE = {
    idfv:  'A1B2C3D4-E5F6-7890-ABCD-EF1234567890',
    idfa:  '00000000-0000-0000-0000-000000000000',
    keychain: {
        'com.autonavi.amap/udid':         'CLEAR',
        'com.autonavi.amap/vimsi':        'CLEAR',
        'com.autonavi.amap/vimei':        'CLEAR',
        'com.autonavi.amap/tid':          'CLEAR',
        'gd_amap/gd_amap':               'CLEAR',
        'com.amap.adiu.key':             'CLEAR',
        '0.umid_v1/com.autonavi.amap':   'CLEAR',
        'PNS_UniqueId_com.autonavi.amap': 'CLEAR'
    },
    userdefaults: {
        '__AMAP_APP_FIRST__':                     null,
        'appInitMd5':                              null,
        'login_credit':                            null,
        'ATAuthSDK_POP_com.autonavi.amap':         null
    }
};

// ══════════════════════════════════════════════════
// 档案加载（优先读 /var/mobile/Documents/amap_profiles/active.json）
// ══════════════════════════════════════════════════

var PROFILE = BUILTIN_PROFILE;

// NSFileManager.defaultManager() 在 spawn-paused 阶段会崩溃（ObjC 单例 + 主线程未启动）。
// 改用纯 C fopen/fread，不依赖 ObjC，可在任意时机安全调用。
(function loadProfile() {
    try {
        var fopen  = new NativeFunction(Module.findExportByName(null, 'fopen'),  'pointer', ['pointer', 'pointer']);
        var fseek  = new NativeFunction(Module.findExportByName(null, 'fseek'),  'int',     ['pointer', 'long', 'int']);
        var ftell  = new NativeFunction(Module.findExportByName(null, 'ftell'),  'long',    ['pointer']);
        var fread  = new NativeFunction(Module.findExportByName(null, 'fread'),  'size_t',  ['pointer', 'size_t', 'size_t', 'pointer']);
        var fclose = new NativeFunction(Module.findExportByName(null, 'fclose'), 'int',     ['pointer']);

        var path = '/var/mobile/Documents/amap_profiles/active.json';
        var fp   = fopen(Memory.allocUtf8String(path), Memory.allocUtf8String('r'));
        if (fp.isNull()) { console.log('[spoof] using built-in profile'); return; }

        fseek(fp, 0, 2); // SEEK_END
        var size = ftell(fp);
        fseek(fp, 0, 0); // SEEK_SET

        if (size > 0 && size < 65536) {
            var buf = Memory.alloc(size + 1);
            fread(buf, 1, size, fp);
            Memory.writeU8(buf.add(size), 0);
            PROFILE = JSON.parse(buf.readUtf8String());
            console.log('[spoof] profile loaded from ' + path);
        } else {
            console.log('[spoof] using built-in profile');
        }
        fclose(fp);
    } catch(e) {
        console.log('[spoof] using built-in profile');
    }
})();

// ══════════════════════════════════════════════════
// 工具：构造 NSUUID / NSString ObjC 对象
// ══════════════════════════════════════════════════

function makeNSUUID(uuidStr) {
    return ObjC.classes.NSUUID.alloc().initWithUUIDString_(uuidStr);
}

function makeNSString(s) {
    return ObjC.classes.NSString.stringWithString_(s);
}

// ══════════════════════════════════════════════════
// 1. IDFV 伪装：[UIDevice identifierForVendor]
// ══════════════════════════════════════════════════

var UIDevice = ObjC.classes.UIDevice;
if (UIDevice) {
    Interceptor.attach(
        UIDevice['- identifierForVendor'].implementation,
        {
            onLeave: function(retval) {
                retval.replace(makeNSUUID(PROFILE.idfv));
            }
        }
    );
    console.log('[spoof] UIDevice.identifierForVendor hooked');
}

// ══════════════════════════════════════════════════
// 2. IDFA 伪装：ASIdentifierManager.advertisingIdentifier
// ══════════════════════════════════════════════════

try {
    var ASIM = ObjC.classes.ASIdentifierManager;
    if (ASIM) {
        Interceptor.attach(
            ASIM['- advertisingIdentifier'].implementation,
            {
                onLeave: function(retval) {
                    retval.replace(makeNSUUID(PROFILE.idfa));
                }
            }
        );
        console.log('[spoof] ASIdentifierManager.advertisingIdentifier hooked');
    }
} catch(e) {}

// ══════════════════════════════════════════════════
// 3. Keychain 伪装：SecItemCopyMatching
// ══════════════════════════════════════════════════

// 从 Security.framework 获取常量地址（带空值检查，避免 spawn 暂停阶段崩溃）
function _secPtr(name) {
    var addr = Module.findExportByName('Security', name);
    if (!addr) return ptr(0);
    try { return Memory.readPointer(addr); } catch(e) { return ptr(0); }
}
var SEC = {
    kSecClass:                _secPtr('kSecClass'),
    kSecAttrService:          _secPtr('kSecAttrService'),
    kSecAttrAccount:          _secPtr('kSecAttrAccount'),
    kSecClassGenericPassword: _secPtr('kSecClassGenericPassword'),
    kSecValueData:            _secPtr('kSecValueData'),
    kSecReturnData:           _secPtr('kSecReturnData'),
    kSecReturnAttributes:     _secPtr('kSecReturnAttributes'),
    kSecMatchLimit:           _secPtr('kSecMatchLimit'),
    kSecMatchLimitOne:        _secPtr('kSecMatchLimitOne'),
    kSecMatchLimitAll:        _secPtr('kSecMatchLimitAll'),
};

function queryKey(queryDict) {
    try {
        var cls     = queryDict.objectForKey_(SEC.kSecClass);
        var service = queryDict.objectForKey_(SEC.kSecAttrService);
        var account = queryDict.objectForKey_(SEC.kSecAttrAccount);
        if (!service || !account) return null;
        return service.toString() + '/' + account.toString();
    } catch(e) {
        return null;
    }
}

function makeNSDataFromString(str) {
    var cStr = Memory.allocUtf8String(str);
    return ObjC.classes.NSData.alloc().initWithBytes_length_(cStr, str.length);
}

var SecItemCopyMatching = Module.findExportByName('Security', 'SecItemCopyMatching');
if (SecItemCopyMatching) {
    Interceptor.attach(SecItemCopyMatching, {
        onEnter: function(args) {
            this.query  = new ObjC.Object(args[0]);
            this.result = args[1]; // OSStatus* result pointer
        },
        onLeave: function(retval) {
            try {
                var key = queryKey(this.query);
                if (!key) return;
                var spoofVal = PROFILE.keychain[key];
                if (spoofVal === undefined) return; // 非目标条目，不干预

                if (spoofVal === 'CLEAR') {
                    // 清除该条目：令调用方拿不到值
                    retval.replace(ptr(-25300)); // errSecItemNotFound
                    if (!this.result.isNull()) Memory.writePointer(this.result, ptr(0));
                    return;
                }

                // 构造返回 NSData
                var dataObj = makeNSDataFromString(spoofVal);
                var returnData = this.query.objectForKey_(SEC.kSecReturnData);
                var returnAttr = this.query.objectForKey_(SEC.kSecReturnAttributes);

                var out;
                if (returnAttr && returnAttr.toString() !== '0') {
                    // 调用方要 attributes dict
                    var dict = ObjC.classes.NSMutableDictionary.alloc().init();
                    dict.setObject_forKey_(dataObj, SEC.kSecValueData);
                    out = dict;
                } else {
                    out = dataObj;
                }

                if (!this.result.isNull()) {
                    Memory.writePointer(this.result, out.handle);
                }
                retval.replace(ptr(0)); // errSecSuccess
                console.log('[spoof] Keychain spoofed: ' + key + ' -> ' + spoofVal.substring(0, 8) + '...');
            } catch(e) {}
        }
    });
    console.log('[spoof] SecItemCopyMatching hooked');
}

// ══════════════════════════════════════════════════
// 4. Keychain 写入拦截：SecItemAdd / SecItemUpdate
//    对目标条目，让写入透传（写真实 Keychain），
//    但记录下值供 backup 阶段使用
// ══════════════════════════════════════════════════

var SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
if (SecItemAdd) {
    Interceptor.attach(SecItemAdd, {
        onEnter: function(args) {
            try {
                var q = new ObjC.Object(args[0]);
                var key = queryKey(q);
                if (key && PROFILE.keychain[key] !== undefined) {
                    console.log('[spoof] SecItemAdd intercepted: ' + key + ' (passthrough)');
                }
            } catch(e) {}
        }
    });
}

var SecItemUpdate = Module.findExportByName('Security', 'SecItemUpdate');
if (SecItemUpdate) {
    Interceptor.attach(SecItemUpdate, {
        onEnter: function(args) {
            try {
                var q = new ObjC.Object(args[0]);
                var key = queryKey(q);
                if (key && PROFILE.keychain[key] !== undefined) {
                    console.log('[spoof] SecItemUpdate intercepted: ' + key + ' (passthrough)');
                }
            } catch(e) {}
        }
    });
}

// ══════════════════════════════════════════════════
// 5. NSUserDefaults 伪装：objectForKey / stringForKey
// ══════════════════════════════════════════════════

// NSUserDefaults 底层由 CFPreferences 实现，+standardUserDefaults 在 spawn 时
// 通过 +resolveClassMethod: 动态解析，class_copyMethodList 无法找到。
// 直接 hook C 函数 CFPreferencesGetAppValue（所有 NSUserDefaults 读最终走这里）。
(function hookCFPreferences() {
    var udKeys = PROFILE.userdefaults;
    try {
        // iOS 16: CFPreferencesGetAppValue 被内联，改用 CFPreferencesCopyAppValue
        var fnPtr = Module.findExportByName(null, 'CFPreferencesCopyAppValue')
                 || Module.findExportByName(null, 'CFPreferencesGetAppValue');
        if (!fnPtr) { console.log('[spoof] CFPreferences hook: function not found'); return; }

        var _cfGetCString = (function() {
            var p = Module.findExportByName('CoreFoundation', 'CFStringGetCString');
            return p ? new NativeFunction(p, 'bool', ['pointer', 'pointer', 'int', 'uint32']) : null;
        })();

        Interceptor.attach(fnPtr, {
            onEnter: function(args) {
                try {
                    if (!_cfGetCString || !args[0] || args[0].isNull()) { this.key = ''; return; }
                    var buf = Memory.alloc(256);
                    _cfGetCString(args[0], buf, 256, 0x08000100);
                    this.key = buf.readUtf8String() || '';
                } catch(e) { this.key = ''; }
            },
            onLeave: function(retval) {
                if (this.key in udKeys && udKeys[this.key] === null) {
                    retval.replace(ptr(0));
                    console.log('[spoof] CFPreferences cleared: ' + this.key);
                }
            }
        });
        console.log('[spoof] CFPreferencesCopyAppValue hooked');
    } catch(e) {
        console.log('[spoof] CFPreferences hook error: ' + e);
    }
})();

// ══════════════════════════════════════════════════
// 6. UIDevice.name 伪装（可选，部分风控读设备名）
// ══════════════════════════════════════════════════

if (UIDevice) {
    try {
        Interceptor.attach(
            UIDevice['- name'].implementation,
            {
                onLeave: function(retval) {
                    retval.replace(makeNSString('iPhone').handle);
                }
            }
        );
    } catch(e) {}
}

console.log('[spoof] ALL identity hooks installed');
