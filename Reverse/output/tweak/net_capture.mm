#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <Security/SecureTransport.h>
#import <dlfcn.h>
#import <substrate.h>
#import "tlog.h"
#import "net_capture.h"
#include <zlib.h>

static BOOL isRelevant(NSString *s) {
    if (!s) return NO;
    return [s containsString:@"gsId"]  || [s containsString:@"adiu"]  ||
           [s containsString:@"risk"]  || [s containsString:@"\"data\":false"] ||
           [s containsString:@"shield"]|| [s containsString:@"passport"] ||
           [s containsString:@"Params error"] || [s containsString:@"\"result\":false"] ||
           [s containsString:@"verifycode"] || [s containsString:@"register"] ||
           [s containsString:@"风险"]  || [s containsString:@"异常"];
}

static NSData *tryGunzip(const uint8_t *p, size_t n) {
    z_stream z = {0};
    z.next_in = (Bytef *)p; z.avail_in = (uInt)n;
    if (inflateInit2(&z, 16 + MAX_WBITS) != Z_OK) return nil;
    NSMutableData *out = [NSMutableData dataWithCapacity:n * 3];
    uint8_t tmp[4096];
    int ret;
    do {
        z.next_out = tmp; z.avail_out = sizeof(tmp);
        ret = inflate(&z, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) break;
        [out appendBytes:tmp length:sizeof(tmp) - z.avail_out];
    } while (ret != Z_STREAM_END);
    inflateEnd(&z);
    return (ret == Z_STREAM_END) ? out : nil;
}

// HTTP/1.1 response with gzip body: decode headers (Latin-1) + gunzip body
static NSString *tryHTTP1Decode(const uint8_t *buf, size_t len) {
    NSString *lat = [[NSString alloc] initWithBytes:buf length:MIN(len,2048) encoding:NSISOLatin1StringEncoding];
    if (!lat) return nil;
    NSRange sep = [lat rangeOfString:@"\r\n\r\n"];
    if (sep.location == NSNotFound) return nil;
    size_t off = sep.location + 4;
    NSData *gz = off < len ? tryGunzip(buf + off, len - off) : nil;
    if (gz) {
        NSString *body = [[NSString alloc] initWithData:gz encoding:NSUTF8StringEncoding];
        if (body) return [lat stringByAppendingString:body];
    }
    return lat;
}

// HTTP/2 DATA frame: [3B len][1B type=0x00][1B flags][4B stream_id][payload]
static NSString *tryH2Decode(const uint8_t *buf, size_t len) {
    if (len < 10 || buf[3] != 0x00) return nil;
    uint32_t plen = ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
    size_t off = 9 + ((buf[4] & 0x08) && len > 9 ? 1 : 0);
    size_t pay = MIN(plen, len > off ? len - off : 0);
    if (!pay) return nil;
    NSData *gz = tryGunzip(buf + off, pay);
    return gz ? [[NSString alloc] initWithData:gz encoding:NSUTF8StringEncoding]
              : [[NSString alloc] initWithBytes:buf + off length:pay encoding:NSUTF8StringEncoding];
}

static NSString *decodeSSL(const uint8_t *buf, size_t len) {
    NSString *s = [[NSString alloc] initWithBytes:buf length:len encoding:NSUTF8StringEncoding];
    return s ?: tryHTTP1Decode(buf, len) ?: tryH2Decode(buf, len);
}

static OSStatus (*orig_SSLRead)(SSLContextRef, void *, size_t, size_t *);
static OSStatus hook_SSLRead(SSLContextRef ctx, void *data, size_t dataLen, size_t *processed) {
    OSStatus r = orig_SSLRead(ctx, data, dataLen, processed);
    if (r != 0 || !processed || *processed < 9) return r;
    @try {
        NSString *s = decodeSSL((const uint8_t *)data, *processed);
        char host[128] = {0};
        size_t hlen = sizeof(host);
        SSLGetPeerDomainName(ctx, host, &hlen);
        BOOL logAll = host[0] && strncmp(host, "passport", 8) == 0;
        if (logAll || isRelevant(s))
            tlog(@"ssl_resp", @{@"h": @(host), @"s": s ? (s.length > 600 ? [s substringToIndex:600] : s) : @"[nil]"});
    } @catch(id e) {}
    return r;
}

static OSStatus (*orig_SSLWrite)(SSLContextRef, const void *, size_t, size_t *);
static OSStatus hook_SSLWrite(SSLContextRef ctx, const void *data, size_t dataLen, size_t *processed) {
    @try {
        if (dataLen > 10) {
            NSString *s = [[NSString alloc] initWithBytes:data length:MIN(dataLen, 300) encoding:NSUTF8StringEncoding];
            if (s && ([s containsString:@"shield"] || [s containsString:@"passport"] ||
                      [s containsString:@"adiu"] || [s containsString:@"amap.com"]))
                tlog(@"ssl_req", @{@"s": s.length > 300 ? [s substringToIndex:300] : s});
        }
    } @catch(id e) {}
    return orig_SSLWrite(ctx, data, dataLen, processed);
}

@interface AmapNetSpy : NSObject
@property (nonatomic, strong) id real;
@end

@implementation AmapNetSpy

- (BOOL)respondsToSelector:(SEL)s {
    if (class_respondsToSelector([AmapNetSpy class], s)) return YES;
    return self.real && [self.real respondsToSelector:s];
}

- (id)forwardingTargetForSelector:(SEL)s {
    return self.real;
}

- (void)URLSession:(NSURLSession *)sess dataTask:(NSURLSessionDataTask *)t didReceiveData:(NSData *)d {
    @try {
        NSString *u = t.currentRequest.URL.absoluteString ?: @"";
        if ([u containsString:@"amap.com"]) {
            NSString *b = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] ?: @"[bin]";
            tlog(@"resp_data", @{
                @"u": u.length > 120 ? [u substringToIndex:120] : u,
                @"b": b.length > 300 ? [b substringToIndex:300] : b
            });
        }
    } @catch(id e) {}
    id r = self.real;
    if (r && [r respondsToSelector:_cmd])
        [r URLSession:sess dataTask:t didReceiveData:d];
}

- (void)URLSession:(NSURLSession *)sess task:(NSURLSessionTask *)t didCompleteWithError:(NSError *)e {
    @try {
        NSString *u = t.currentRequest.URL.absoluteString ?: @"";
        if ([u containsString:@"amap.com"])
            tlog(@"resp_done", @{
                @"u": u.length > 120 ? [u substringToIndex:120] : u,
                @"e": e.localizedDescription ?: @""
            });
    } @catch(id e2) {}
    id r = self.real;
    if (r && [r respondsToSelector:_cmd])
        [r URLSession:sess task:t didCompleteWithError:e];
}

@end

static id (*orig_newSess)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
static id hook_newSess(id s, SEL c, NSURLSessionConfiguration *cfg, id d, NSOperationQueue *q) {
    if (d) {
        AmapNetSpy *spy = [AmapNetSpy new];
        spy.real = d;
        d = spy;
    }
    return orig_newSess(s, c, cfg, d, q);
}

void installNetCaptureHooks(void) {
    void *fnr = dlsym(RTLD_DEFAULT, "SSLRead");
    if (fnr) MSHookFunction(fnr, (void *)hook_SSLRead, (void **)&orig_SSLRead);
    void *fnw = dlsym(RTLD_DEFAULT, "SSLWrite");
    if (fnw) MSHookFunction(fnw, (void *)hook_SSLWrite, (void **)&orig_SSLWrite);
    MSHookMessageEx(
        object_getClass(NSClassFromString(@"NSURLSession")),
        @selector(sessionWithConfiguration:delegate:delegateQueue:),
        (IMP)hook_newSess,
        (IMP *)&orig_newSess);
}
