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
// 2. CFNetwork: SSLHandshake
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
