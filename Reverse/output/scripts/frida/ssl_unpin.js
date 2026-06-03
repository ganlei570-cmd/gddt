// ssl_unpin.js — iOS SSL 证书验证绕过
// 目的：让 mitmproxy 能解密高德 HTTPS 流量（配合代理模式使用）
// 加载顺序：-l bypass.js -l ssl_unpin.js -l spoof.js
// 职责：只做 SSL 证书验证绕过，不做其他事

'use strict';

// ══════════════════════════════════════════════════
// 1. SecTrustEvaluate / SecTrustEvaluateWithError
// ══════════════════════════════════════════════════

var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
if (SecTrustEvaluate) {
    Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
        // kSecTrustResultProceed = 1
        if (result && !ptr(result).isNull()) Memory.writeU32(result, 1);
        return 0; // errSecSuccess
    }, 'int', ['pointer', 'pointer']));
    console.log('[ssl_unpin] SecTrustEvaluate patched');
}

var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
if (SecTrustEvaluateWithError) {
    Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function(trust, error) {
        if (error && !ptr(error).isNull()) Memory.writePointer(error, ptr(0));
        return 1; // true = trusted
    }, 'bool', ['pointer', 'pointer']));
    console.log('[ssl_unpin] SecTrustEvaluateWithError patched');
}

// ══════════════════════════════════════════════════
// 2. NSURLSession didReceiveChallenge delegate bypass
// ══════════════════════════════════════════════════

try {
    var NSURLSessionClass = ObjC.classes.NSURLSession;
    if (NSURLSessionClass) {
        // Hook completionHandler 调用，强制 NSURLSessionAuthChallengeUseCredential
        // 实际在 CFNetwork 层拦截更可靠，此处做 ObjC delegate 层保险
    }
} catch(e) {}

// ══════════════════════════════════════════════════
// 3. CFNetwork: SSLHandshake / tls_helper_create_peer_trust
// ══════════════════════════════════════════════════

var SSLHandshake = Module.findExportByName('Security', 'SSLHandshake');
if (SSLHandshake) {
    Interceptor.attach(SSLHandshake, {
        onLeave: function(retval) {
            retval.replace(ptr(0)); // noErr
        }
    });
}

// ══════════════════════════════════════════════════
// 4. 绕过 App 内置证书 Pinning
//    hook -[NSURLSession URLSession:didReceiveChallenge:completionHandler:]
// ══════════════════════════════════════════════════

if (ObjC.available) {
    try {
        var NSURLCredential = ObjC.classes.NSURLCredential;
        var challengeSel = ObjC.selector('URLSession:didReceiveChallenge:completionHandler:');

        // 枚举所有实现了该 delegate 方法的类
        ObjC.enumerateLoadedClasses({
            onMatch: function(name, handle) {
                try {
                    var cls = ObjC.classes[name];
                    if (!cls) return;
                    if (!cls['- URLSession:didReceiveChallenge:completionHandler:']) return;
                    var impl = cls['- URLSession:didReceiveChallenge:completionHandler:'].implementation;
                    Interceptor.attach(impl, {
                        onEnter: function(args) {
                            try {
                                var challenge    = new ObjC.Object(args[3]);
                                var protSpace    = challenge.protectionSpace();
                                var authMethod   = protSpace.authenticationMethod().toString();
                                if (authMethod.indexOf('ServerTrust') < 0) return;
                                var trust        = protSpace.serverTrust();
                                var credential   = NSURLCredential.credentialForTrust_(trust);
                                var completionHandler = new ObjC.Block(args[4]);
                                // NSURLSessionAuthChallengeUseCredential = 0
                                completionHandler.implementation(0, credential.handle);
                                this.handled = true;
                            } catch(e) {}
                        }
                    });
                } catch(e) {}
            },
            onComplete: function() {}
        });
        console.log('[ssl_unpin] NSURLSession challenge delegate hooks installed');
    } catch(e) {
        console.log('[ssl_unpin] challenge hook skipped: ' + e);
    }
}

// ══════════════════════════════════════════════════
// 5. 针对 DTHbalSe 的 BoringSSL / OpenSSL 层 Hook
// ══════════════════════════════════════════════════

var SSL_CTX_set_custom_verify = Module.findExportByName(null, 'SSL_CTX_set_custom_verify');
if (SSL_CTX_set_custom_verify) {
    Interceptor.attach(SSL_CTX_set_custom_verify, {
        onEnter: function(args) {
            // 替换验证回调为空函数，所有证书都通过
            var noop = new NativeCallback(function() { return 0; }, 'int', ['pointer', 'pointer']);
            args[1] = noop;
        }
    });
}

var SSL_CTX_set_verify = Module.findExportByName(null, 'SSL_CTX_set_verify');
if (SSL_CTX_set_verify) {
    Interceptor.attach(SSL_CTX_set_verify, {
        onEnter: function(args) {
            args[1] = ptr(1); // SSL_VERIFY_NONE
        }
    });
}

console.log('[ssl_unpin] ALL SSL unpin hooks installed');
