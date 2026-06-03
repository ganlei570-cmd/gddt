// net_capture.js — 一次性，用完删
// 多层 Hook：NSURLSession + CFNetwork + send/recv 系统调用
// 捕获高德 + 阿里风控的所有出站 HTTP 请求（明文，加密前）

'use strict';

var CAPTURE_DOMAINS = [
    'amap.com', 'autonavi.com',
    'ynuf.aliapp.org', 'ynuf.alipay.com',
    'amdc.m.taobao.com', 'log.mmstat.com',
    'security.alibaba.com', 'tb.cn',
    'amap.com', 'aliyuncs.com', 'alibaba.com',
];

var RISK_KEYWORDS = [
    'risk', 'device', 'fingerprint', 'umid', 'udid', 'imei',
    'did', 'report', 'collect', 'shield', 'dth', 'um.json',
    'appmonitor', 'security', 'check', 'bootevent', 'preheat',
    'diagnose', 'register', 'ding', 'mtop',
];

function domainMatch(url) {
    if (!url) return false;
    var l = url.toLowerCase();
    for (var i = 0; i < CAPTURE_DOMAINS.length; i++) {
        if (l.indexOf(CAPTURE_DOMAINS[i]) >= 0) return true;
    }
    return false;
}

function isRisk(url) {
    if (!url) return false;
    var lurl = url.toLowerCase();
    for (var i = 0; i < RISK_KEYWORDS.length; i++) {
        if (lurl.indexOf(RISK_KEYWORDS[i]) >= 0) return true;
    }
    return false;
}

function safeStr(nsdata) {
    if (!nsdata) return '';
    try {
        if (typeof nsdata === 'string') return nsdata;
        var o = nsdata.handle ? nsdata : new ObjC.Object(nsdata);
        if (o.handle.isNull()) return '';
        var s = ObjC.classes.NSString.alloc().initWithData_encoding_(o, 4);
        if (s && !s.handle.isNull()) return s.toString();
        return o.base64EncodedStringWithOptions_(0).toString();
    } catch(e) { return ''; }
}

function headersToObj(nsd) {
    var obj = {};
    try {
        if (!nsd || nsd.handle.isNull()) return obj;
        var keys = nsd.allKeys();
        for (var i = 0; i < keys.count().valueOf(); i++) {
            var k = keys.objectAtIndex_(i).toString();
            var v = nsd.objectForKey_(k);
            obj[k] = v ? v.toString() : '';
        }
    } catch(e) {}
    return obj;
}

function emit(url, method, headers, body) {
    send({
        type:    'request',
        url:     url,
        method:  method,
        headers: headers,
        body:    body,
        is_risk: isRisk(url),
    });
}

// ── Layer 1: NSURLSession ─────────────────────────────────────
var bodyCache = {};  // NSMutableURLRequest 地址 → body 字符串

try {
    var NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
    if (NSMutableURLRequest) {
        Interceptor.attach(NSMutableURLRequest['- setHTTPBody:'].implementation, {
            onEnter: function(args) {
                try {
                    bodyCache[args[0].toString()] = safeStr(new ObjC.Object(args[2]));
                } catch(e) {}
            }
        });
    }
} catch(e) {}

function hookSession(sel) {
    try {
        var impl = ObjC.classes.NSURLSession[sel];
        if (!impl) return;
        Interceptor.attach(impl.implementation, {
            onEnter: function(args) {
                try {
                    var req = new ObjC.Object(args[2]);
                    var url = req.URL().absoluteString().toString();
                    if (!domainMatch(url)) return;
                    emit(url,
                        req.HTTPMethod().toString(),
                        headersToObj(req.allHTTPHeaderFields()),
                        safeStr(req.HTTPBody()) || bodyCache[args[2].toString()] || ''
                    );
                } catch(e) {}
            }
        });
    } catch(e) {}
}

hookSession('- dataTaskWithRequest:completionHandler:');
hookSession('- dataTaskWithRequest:');
hookSession('- uploadTaskWithRequest:fromData:completionHandler:');
hookSession('- uploadTaskWithRequest:fromData:');

// ── Layer 2: CFNetwork CFURLRequestRef ────────────────────────
// DTHbalSe 可能绕过 NSURLSession 直接用 CFNetwork
try {
    var CFHTTPMessageAddAuthentication = Module.findExportByName('CFNetwork', 'CFHTTPMessageCopyHeaderFieldValue');
    // Hook CFURLConnectionSendAsynchronousRequest
    var cfAsync = Module.findExportByName('CFNetwork', 'CFURLConnectionSendAsynchronousRequest');
    if (cfAsync) {
        Interceptor.attach(cfAsync, {
            onEnter: function(args) {
                try {
                    var req = new ObjC.Object(args[0]);
                    var url = req.URL ? req.URL().absoluteString().toString() : '?';
                    if (!domainMatch(url)) return;
                    emit(url, 'CF-ASYNC', {}, '');
                } catch(e) {}
            }
        });
    }
} catch(e) {}

// ── Layer 3: 在 send() 系统调用层捕获原始 HTTP 文本 ───────────
// 捕获含 "Host:" 头的 TCP 发送（明文 HTTP 或 TLS 握手前）
try {
    var sendPtr = Module.findExportByName(null, 'send');
    if (sendPtr) {
        Interceptor.attach(sendPtr, {
            onEnter: function(args) {
                try {
                    var len = args[2].toInt32();
                    if (len < 20 || len > 8192) return;
                    var buf = Memory.readByteArray(args[1], Math.min(len, 512));
                    var str = String.fromCharCode.apply(null, new Uint8Array(buf));
                    if (str.indexOf('Host:') < 0) return; // 只处理 HTTP 文本
                    // 提取 Host 和 URL
                    var hostMatch = str.match(/Host:\s*([^\r\n]+)/);
                    var pathMatch = str.match(/^[A-Z]+ ([^\s]+)/);
                    if (!hostMatch) return;
                    var host = hostMatch[1].trim();
                    if (!domainMatch('https://' + host + '/')) return;
                    var path = pathMatch ? pathMatch[1] : '/';
                    var bodyStart = str.indexOf('\r\n\r\n');
                    var body = bodyStart >= 0 ? str.substring(bodyStart + 4, 256) : '';
                    emit('https://' + host + path, 'TCP-RAW', {}, body);
                } catch(e) {}
            }
        });
    }
} catch(e) {}

// ── Layer 4: NSURLSession didReceiveData 捕获响应 ──────────────
// （可选，用于观察风控服务端返回值）
try {
    var NSURLSessionDataTask = ObjC.classes.NSURLSessionDataTask;
    if (NSURLSessionDataTask) {
        var resumeImpl = NSURLSessionDataTask['- resume'].implementation;
        if (resumeImpl) {
            Interceptor.attach(resumeImpl, {
                onEnter: function(args) {
                    try {
                        var task    = new ObjC.Object(args[0]);
                        var origReq = task.originalRequest();
                        if (!origReq || origReq.handle.isNull()) return;
                        var url = origReq.URL().absoluteString().toString();
                        if (!domainMatch(url)) return;
                        console.log('[net_capture] task.resume: ' + url.substring(0, 80));
                    } catch(e) {}
                }
            });
        }
    }
} catch(e) {}

// ── 额外：Hook IDFV，用于验证 spoof.js 是否生效 ────────────
try {
    var UIDevice = ObjC.classes.UIDevice;
    if (UIDevice) {
        Interceptor.attach(UIDevice['- identifierForVendor'].implementation, {
            onLeave: function(retval) {
                try {
                    var uuid = new ObjC.Object(retval);
                    send({ type: 'idfv', value: uuid.UUIDString().toString() });
                } catch(e) {}
            }
        });
    }
} catch(e) {}

send({ type: 'ready' });
console.log('[net_capture] ALL layers hooked (NSURLSession + CFNetwork + send syscall)');
