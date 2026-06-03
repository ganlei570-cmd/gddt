// login_probe.js — 一次性，用完删
// 用途：在高德地图登录流程中，捕获所有登录态写入点
// 使用方式：
//   1. 先完成登录操作（进入高德并登录账号）
//   2. 加载本脚本，观察 console 输出
//   3. 把输出贴给 Claude 分析，确认备份字段清单
// 加载命令：
//   python -c "
//   import frida,sys,io,time
//   sys.stdout=io.TextIOWrapper(sys.stdout.buffer,encoding='utf-8')
//   dev=frida.get_device('fcb0b05ae20229767149e98cb3ac94dcde52f74f')
//   pid=dev.spawn(['com.autonavi.amap'])
//   session=dev.attach(pid)
//   for f in ['bypass.js','debug/login_probe.js']:
//     s=session.create_script(open(f'Reverse/output/scripts/frida/{f}',encoding='utf-8').read())
//     s.on('message',lambda m,d: print(m))
//     s.load()
//   dev.resume(pid)
//   time.sleep(120)
//   "

'use strict';

// ══════════════════════════════════════════════════
// 1. Keychain 写入（SecItemAdd / SecItemUpdate）
// ══════════════════════════════════════════════════

var SEC = {
    kSecAttrService: Memory.readPointer(Module.findExportByName('Security', 'kSecAttrService')),
    kSecAttrAccount: Memory.readPointer(Module.findExportByName('Security', 'kSecAttrAccount')),
    kSecValueData:   Memory.readPointer(Module.findExportByName('Security', 'kSecValueData')),
};

function logKeychainQuery(label, queryObj) {
    try {
        var q = new ObjC.Object(queryObj);
        var service = q.objectForKey_(SEC.kSecAttrService);
        var account = q.objectForKey_(SEC.kSecAttrAccount);
        var data    = q.objectForKey_(SEC.kSecValueData);
        var svc = service ? service.toString() : '(none)';
        var acc = account ? account.toString() : '(none)';
        var preview = '';
        if (data && !data.handle.isNull()) {
            try {
                var str = ObjC.classes.NSString.alloc().initWithData_encoding_(data, 4);
                preview = str ? str.toString().substring(0, 80) : data.base64EncodedStringWithOptions_(0).toString().substring(0, 80);
            } catch(e) {
                preview = '[binary]';
            }
        }
        console.log('[KEYCHAIN-WRITE] ' + label + ' | service=' + svc + ' | account=' + acc);
        if (preview) console.log('  data_preview: ' + preview);
    } catch(e) {}
}

var SecItemAdd = Module.findExportByName('Security', 'SecItemAdd');
if (SecItemAdd) {
    Interceptor.attach(SecItemAdd, {
        onEnter: function(args) { logKeychainQuery('SecItemAdd', args[0]); }
    });
}

var SecItemUpdate = Module.findExportByName('Security', 'SecItemUpdate');
if (SecItemUpdate) {
    Interceptor.attach(SecItemUpdate, {
        onEnter: function(args) { logKeychainQuery('SecItemUpdate', args[0]); }
    });
}

// ══════════════════════════════════════════════════
// 2. Cookie 写入（NSHTTPCookieStorage）
// ══════════════════════════════════════════════════

var CookieStorage = ObjC.classes.NSHTTPCookieStorage;
if (CookieStorage) {
    Interceptor.attach(
        CookieStorage['- setCookie:'].implementation,
        {
            onEnter: function(args) {
                try {
                    var cookie = new ObjC.Object(args[2]);
                    var name   = cookie.name().toString();
                    var domain = cookie.domain().toString();
                    var value  = cookie.value().toString();
                    console.log('[COOKIE-SET] ' + domain + ' | ' + name + '=' + value.substring(0, 60));
                } catch(e) {}
            }
        }
    );
    Interceptor.attach(
        CookieStorage['- setCookies:forURL:mainDocumentURL:'].implementation,
        {
            onEnter: function(args) {
                try {
                    var cookies = new ObjC.Object(args[2]);
                    var url     = args[3];
                    var urlStr  = url && !ptr(url).isNull() ? new ObjC.Object(url).absoluteString().toString() : '?';
                    var count   = cookies.count().valueOf();
                    for (var i = 0; i < count; i++) {
                        var c = cookies.objectAtIndex_(i);
                        console.log('[COOKIE-BULK] url=' + urlStr.substring(0, 60) + ' | ' + c.name() + '=' + c.value().toString().substring(0, 40));
                    }
                } catch(e) {}
            }
        }
    );
}

// ══════════════════════════════════════════════════
// 3. NSUserDefaults 写入（setObject:forKey:）
// ══════════════════════════════════════════════════

var NSUserDefaults = ObjC.classes.NSUserDefaults;
if (NSUserDefaults) {
    Interceptor.attach(
        NSUserDefaults['- setObject:forKey:'].implementation,
        {
            onEnter: function(args) {
                try {
                    var key = new ObjC.Object(args[3]).toString();
                    // 只记录疑似登录相关的 key
                    var lk = key.toLowerCase();
                    if (lk.indexOf('login') >= 0 || lk.indexOf('token') >= 0 ||
                        lk.indexOf('uid') >= 0   || lk.indexOf('user') >= 0 ||
                        lk.indexOf('auth') >= 0  || lk.indexOf('session') >= 0 ||
                        lk.indexOf('credit') >= 0 || lk.indexOf('ticket') >= 0 ||
                        lk.indexOf('amap') >= 0) {
                        var val = new ObjC.Object(args[2]);
                        var valStr = '(nil)';
                        try { valStr = val.toString().substring(0, 80); } catch(e) {}
                        console.log('[UD-WRITE] key=' + key + ' | value=' + valStr);
                    }
                } catch(e) {}
            }
        }
    );
}

// ══════════════════════════════════════════════════
// 4. SQLite 写入（INSERT/UPDATE 含关键字）
// ══════════════════════════════════════════════════

var sqlite3_exec = Module.findExportByName(null, 'sqlite3_exec');
if (sqlite3_exec) {
    Interceptor.attach(sqlite3_exec, {
        onEnter: function(args) {
            try {
                var sql = args[1].readUtf8String();
                if (!sql) return;
                var s = sql.toUpperCase();
                if ((s.indexOf('INSERT') >= 0 || s.indexOf('UPDATE') >= 0) &&
                    (s.indexOf('LOGIN') >= 0 || s.indexOf('USER') >= 0 ||
                     s.indexOf('TOKEN') >= 0 || s.indexOf('SESSION') >= 0 ||
                     s.indexOf('AUTH') >= 0  || s.indexOf('COOKIE') >= 0)) {
                    console.log('[SQLITE-WRITE] ' + sql.substring(0, 200));
                }
            } catch(e) {}
        }
    });
}

// ══════════════════════════════════════════════════
// 5. 扫描沙盒内所有 .db / .sqlite 文件
// ══════════════════════════════════════════════════

(function scanDB() {
    try {
        var NSFileManager = ObjC.classes.NSFileManager;
        var NSSearchPathForDirectoriesInDomains = new NativeFunction(
            Module.findExportByName(null, 'NSSearchPathForDirectoriesInDomains'),
            'pointer', ['int', 'int', 'bool']
        );
        // Library = 5, NSUserDomainMask = 1
        var dirs = new ObjC.Object(NSSearchPathForDirectoriesInDomains(5, 1, 1));
        var libDir = dirs.objectAtIndex_(0).toString();
        // 也搜 Documents
        var docDirs = new ObjC.Object(NSSearchPathForDirectoriesInDomains(9, 1, 1));
        var docDir  = docDirs.objectAtIndex_(0).toString();

        var searchDirs = [libDir, docDir];
        var fm = NSFileManager.defaultManager();
        var exts = ['.db', '.sqlite', '.sqlite3'];

        searchDirs.forEach(function(dir) {
            try {
                var enumerator = fm.enumeratorAtPath_(dir);
                var file;
                while ((file = enumerator.nextObject()) !== null && !file.handle.isNull()) {
                    var name = file.toString().toLowerCase();
                    for (var i = 0; i < exts.length; i++) {
                        if (name.endsWith(exts[i])) {
                            console.log('[DB-FILE] ' + dir + '/' + file.toString());
                            break;
                        }
                    }
                }
            } catch(e) {}
        });
    } catch(e) {}
})();

// ══════════════════════════════════════════════════
// 6. 打印当前所有 NSHTTPCookieStorage cookies
// ══════════════════════════════════════════════════

(function dumpCurrentCookies() {
    try {
        var storage = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage();
        var cookies = storage.cookies();
        var count   = cookies.count().valueOf();
        console.log('[COOKIE-DUMP] 当前 cookie 总数: ' + count);
        for (var i = 0; i < count; i++) {
            var c = cookies.objectAtIndex_(i);
            console.log('[COOKIE-DUMP] ' + c.domain() + ' | ' + c.name() + '=' + c.value().toString().substring(0, 60));
        }
    } catch(e) {}
})();

// ══════════════════════════════════════════════════
// 7. 打印当前 NSUserDefaults 全部内容
// ══════════════════════════════════════════════════

(function dumpCurrentUD() {
    try {
        var ud   = ObjC.classes.NSUserDefaults.standardUserDefaults();
        var dict = ud.dictionaryRepresentation();
        var keys = dict.allKeys();
        var n    = keys.count().valueOf();
        for (var i = 0; i < n; i++) {
            var k  = keys.objectAtIndex_(i).toString();
            var kl = k.toLowerCase();
            if (kl.indexOf('login') >= 0 || kl.indexOf('token') >= 0 ||
                kl.indexOf('uid') >= 0   || kl.indexOf('user') >= 0 ||
                kl.indexOf('auth') >= 0  || kl.indexOf('session') >= 0 ||
                kl.indexOf('credit') >= 0 || kl.indexOf('amap') >= 0) {
                var v = dict.objectForKey_(k);
                var vs = '?';
                try { vs = v.toString().substring(0, 80); } catch(e2) {}
                console.log('[UD-DUMP] ' + k + ' = ' + vs);
            }
        }
    } catch(e) {}
})();

console.log('[login_probe] ALL probes installed — 请在高德地图内完成登录操作');
