// bypass.js — 绕过高德 DTHbalSe + 主二进制的所有检测
// 必须在 spawn 暂停阶段加载，resume 前 Hook 到位
// 职责：只做检测绕过，不做其他事

'use strict';

// ── 强制初始化 Frida ObjC 桥（必须在 dyld hook 安装之前）──
// 原因：ObjC 桥初始化时会调用 _dyld_image_count/_dyld_get_image_name 扫描 ObjC 元数据。
// 如果在装 dyld hook 之后才初始化，桥会拿到被过滤的索引，导致后续脚本（spoof.js）
// 的 ObjC.classes.* 访问失败/连接断开。提前触发初始化可以规避这个问题。
try { var _OBJ_BRIDGE_ = ObjC.classes.NSObject; } catch(e) {}

// ─── 越狱路径黑名单（fopen / access / stat 拦截用）───
var JAILBREAK_PATHS = [
    '/Applications/Cydia.app',
    '/Applications/Sileo.app',
    '/Applications/Zebra.app',
    '/Library/MobileSubstrate',
    '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/usr/sbin/sshd',
    '/usr/bin/ssh',
    '/etc/apt',
    '/private/var/lib/apt',
    '/private/var/stash',
    '/private/var/db/stash',
    '/usr/lib/substrate',
    '/usr/lib/TweakInject',
    '/usr/lib/ellekit',
    '/private/preboot',
    'systemhook',
    'ElleKit',
    'frida',
    'FridaGadget',
    'cynject',
    'substitute',
];

// ─── Frida 相关 dylib 名称（_dyld_image 枚举拦截用）───
var FRIDA_DYLIB_KEYWORDS = [
    'frida', 'FridaGadget', 'frida-agent',
    'systemhook', 'ElleKit', 'substrate',
    'TweakInject', 'cynject', 'substitute',
];

function pathIsJailbreak(path) {
    if (!path) return false;
    for (var i = 0; i < JAILBREAK_PATHS.length; i++) {
        if (path.indexOf(JAILBREAK_PATHS[i]) >= 0) return true;
    }
    return false;
}

function dylibIsFrida(name) {
    if (!name) return false;
    var lower = name.toLowerCase();
    for (var i = 0; i < FRIDA_DYLIB_KEYWORDS.length; i++) {
        if (lower.indexOf(FRIDA_DYLIB_KEYWORDS[i].toLowerCase()) >= 0) return true;
    }
    return false;
}

// ══════════════════════════════════════════════════
// 1. 反调试：ptrace / sysctl / task_info / task_get_exception_ports
// ══════════════════════════════════════════════════

var ptracePtr = Module.findExportByName(null, 'ptrace');
if (ptracePtr) {
    Interceptor.attach(ptracePtr, {
        onEnter: function(args) {
            // PT_DENY_ATTACH = 31
            if (args[0].toInt32() === 31) {
                args[0] = ptr(0);
            }
        }
    });
}

var sysctlPtr = Module.findExportByName(null, 'sysctl');
if (sysctlPtr) {
    Interceptor.attach(sysctlPtr, {
        onEnter: function(args) {
            this.args = args;
        },
        onLeave: function(retval) {
            // 清除 P_TRACED 标志（kinfo_proc.kp_proc.p_flag 第 11 位）
            try {
                var mib = this.args[0];
                var ctl0 = Memory.readS32(mib);
                var ctl1 = Memory.readS32(mib.add(4));
                // CTL_KERN=1, KERN_PROC=14
                if (ctl0 === 1 && ctl1 === 14) {
                    var oldp = this.args[2];
                    if (!oldp.isNull()) {
                        // p_flag 偏移 32，清除 P_TRACED(0x800)
                        var flags = Memory.readU32(oldp.add(32));
                        Memory.writeU32(oldp.add(32), flags & ~0x800);
                    }
                }
            } catch(e) {}
        }
    });
}

var taskInfoPtr = Module.findExportByName(null, 'task_info');
if (taskInfoPtr) {
    Interceptor.attach(taskInfoPtr, {
        onLeave: function(retval) {
            retval.replace(ptr(0)); // KERN_SUCCESS，不返回调试信息
        }
    });
}

var taskExcPtr = Module.findExportByName(null, 'task_get_exception_ports');
if (taskExcPtr) {
    Interceptor.attach(taskExcPtr, {
        onLeave: function(retval) {
            retval.replace(ptr(0));
        }
    });
}

// ══════════════════════════════════════════════════
// 2. Frida dylib 检测：_dyld_image_count / _dyld_get_image_name
//
// 方案：在装 Hook 之前先把真实索引表建好（调原始函数，无副作用），
//       然后用 Interceptor.attach (onLeave / onEnter) 而不是 replace，
//       避免破坏 Frida 自己的 ObjC 桥初始化流程。
//
// 注意：_dyld_register_func_for_add_image 不能 no-op，
//       Frida 的 ObjC 桥靠它注册扫描回调——替换成 no-op 会让
//       ObjC.classes.* 拿不到任何类（造成 spoof.js 加载时崩溃）。
// ══════════════════════════════════════════════════

var imageCountPtr = Module.findExportByName(null, '_dyld_image_count');
var imageNamePtr  = Module.findExportByName(null, '_dyld_get_image_name');

// 在装 hook 之前用原始函数建好索引
var realIndices = [];
(function prebuildIndices() {
    if (!imageCountPtr || !imageNamePtr) return;
    var countFn = new NativeFunction(imageCountPtr, 'uint32', []);
    var nameFn  = new NativeFunction(imageNamePtr, 'pointer', ['uint32']);
    var total   = countFn();
    for (var i = 0; i < total; i++) {
        var np   = nameFn(i);
        var name = np.isNull() ? '' : np.readUtf8String();
        if (!dylibIsFrida(name)) realIndices.push(i);
    }
})();

// attach onLeave 修改返回值（不替换函数体，不破坏 Frida 内部调用）
if (imageCountPtr) {
    Interceptor.attach(imageCountPtr, {
        onLeave: function(retval) {
            retval.replace(ptr(realIndices.length));
        }
    });
}

// attach onEnter 重映射索引（改参数，让原函数用真实 index 执行）
if (imageNamePtr) {
    Interceptor.attach(imageNamePtr, {
        onEnter: function(args) {
            var idx = args[0].toInt32();
            args[0] = ptr(idx < realIndices.length ? realIndices[idx] : 0xFFFFFFFF);
        }
    });
}

// _dyld_register_func_for_add_image：只过滤 Frida 自己注册的回调，
// 不做 no-op，让 ObjC 桥的回调正常注册。
var regAddPtr = Module.findExportByName(null, '_dyld_register_func_for_add_image');
if (regAddPtr) {
    Interceptor.attach(regAddPtr, {
        onEnter: function(args) {
            // 什么都不做，让所有回调正常注册（包括 Frida 自己的）
            // 高德只需要过滤 dyld 名称，不需要阻断回调注册
        }
    });
}

// ══════════════════════════════════════════════════
// 3. 端口探测：connect 拦截（阻断 27042 端口扫描）
// ══════════════════════════════════════════════════

var connectPtr = Module.findExportByName(null, 'connect');
if (connectPtr) {
    Interceptor.attach(connectPtr, {
        onEnter: function(args) {
            this.block = false;
            try {
                var sockaddr = args[1];
                var port = Memory.readU8(sockaddr.add(2)) * 256 + Memory.readU8(sockaddr.add(3));
                if (port === 27042 || port === 27043) {
                    this.block = true;
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(ptr(-1));
        }
    });
}

// ══════════════════════════════════════════════════
// 4. 越狱路径检测：access / fopen / stat
// ══════════════════════════════════════════════════

var accessPtr = Module.findExportByName(null, 'access');
if (accessPtr) {
    Interceptor.attach(accessPtr, {
        onEnter: function(args) {
            try {
                this.path = args[0].readUtf8String();
            } catch(e) { this.path = ''; }
            this.block = pathIsJailbreak(this.path);
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(ptr(-1));
        }
    });
}

var fopenPtr = Module.findExportByName(null, 'fopen');
if (fopenPtr) {
    Interceptor.attach(fopenPtr, {
        onEnter: function(args) {
            try {
                this.path = args[0].readUtf8String();
            } catch(e) { this.path = ''; }
            this.block = pathIsJailbreak(this.path);
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(ptr(0));
        }
    });
}

var stat64Ptr = Module.findExportByName(null, 'stat64') || Module.findExportByName(null, 'stat');
if (stat64Ptr) {
    Interceptor.attach(stat64Ptr, {
        onEnter: function(args) {
            try {
                this.path = args[0].readUtf8String();
            } catch(e) { this.path = ''; }
            this.block = pathIsJailbreak(this.path);
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(ptr(-1));
        }
    });
}

// ══════════════════════════════════════════════════
// 5. 环境变量检测：getenv("DYLD_INSERT_LIBRARIES")
// ══════════════════════════════════════════════════

var getenvPtr = Module.findExportByName(null, 'getenv');
if (getenvPtr) {
    Interceptor.attach(getenvPtr, {
        onEnter: function(args) {
            try { this.key = args[0].readUtf8String(); } catch(e) { this.key = ''; }
        },
        onLeave: function(retval) {
            if (this.key === 'DYLD_INSERT_LIBRARIES' || this.key === 'DYLD_LIBRARY_PATH') {
                retval.replace(ptr(0));
            }
        }
    });
}

// ══════════════════════════════════════════════════
// 6. shell 执行检测：popen / system
// ══════════════════════════════════════════════════

var popenPtr = Module.findExportByName(null, 'popen');
if (popenPtr) {
    Interceptor.replace(popenPtr, new NativeCallback(function(cmd, mode) {
        return ptr(0); // 返回 NULL，模拟执行失败
    }, 'pointer', ['pointer', 'pointer']));
}

var systemPtr = Module.findExportByName(null, 'system');
if (systemPtr) {
    Interceptor.replace(systemPtr, new NativeCallback(function(cmd) {
        return 0;
    }, 'int', ['pointer']));
}

// ══════════════════════════════════════════════════
// 7. dlopen 检测：阻止检测 Frida 相关库
// ══════════════════════════════════════════════════

var dlopenPtr = Module.findExportByName(null, 'dlopen');
if (dlopenPtr) {
    Interceptor.attach(dlopenPtr, {
        onEnter: function(args) {
            try {
                this.path = args[0].readUtf8String();
                this.block = dylibIsFrida(this.path);
            } catch(e) { this.block = false; }
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(ptr(0));
        }
    });
}

// ══════════════════════════════════════════════════
// 8. sysctlbyname 检测（DTHbalSe 主要用此）
// ══════════════════════════════════════════════════

var sysctlbynamePtr = Module.findExportByName(null, 'sysctlbyname');
if (sysctlbynamePtr) {
    Interceptor.attach(sysctlbynamePtr, {
        onEnter: function(args) {
            try { this.name = args[0].readUtf8String(); } catch(e) { this.name = ''; }
        },
        onLeave: function(retval) {
            // kern.proc.pid 相关查询：清除 P_TRACED
            if (this.name && this.name.indexOf('proc') >= 0) {
                retval.replace(ptr(-1)); // 返回失败，隐藏进程信息
            }
        }
    });
}

// ══════════════════════════════════════════════════
// 9. 进程自杀拦截：exit / abort / kill(self)
//    DTHbalSe 检测到 Frida 后调 exit(1)，截住它
// ══════════════════════════════════════════════════

var exitPtr = Module.findExportByName(null, 'exit');
if (exitPtr) {
    Interceptor.replace(exitPtr, new NativeCallback(function(code) {
        console.log('[bypass] exit(' + code + ') blocked');
        // 不真正退出，什么都不做
    }, 'void', ['int']));
}

var _exitPtr = Module.findExportByName(null, '_exit');
if (_exitPtr) {
    Interceptor.replace(_exitPtr, new NativeCallback(function(code) {
        console.log('[bypass] _exit(' + code + ') blocked');
    }, 'void', ['int']));
}

var abortPtr = Module.findExportByName(null, 'abort');
if (abortPtr) {
    Interceptor.replace(abortPtr, new NativeCallback(function() {
        console.log('[bypass] abort() blocked');
    }, 'void', []));
}

// kill(getpid(), SIGKILL) 自杀检测
var killPtr = Module.findExportByName(null, 'kill');
if (killPtr) {
    var getpidFn = new NativeFunction(Module.findExportByName(null, 'getpid'), 'int', []);
    Interceptor.attach(killPtr, {
        onEnter: function(args) {
            var targetPid = args[0].toInt32();
            var sig       = args[1].toInt32();
            if (targetPid === getpidFn() && (sig === 9 || sig === 15)) {
                console.log('[bypass] kill(self, ' + sig + ') blocked');
                args[0] = ptr(-1); // 改成无效 pid
            }
        }
    });
}

console.log('[bypass] ALL hooks installed (9 categories)');
