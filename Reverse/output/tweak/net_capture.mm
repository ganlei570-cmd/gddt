#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <Security/SecureTransport.h>
#import <dlfcn.h>
#import <substrate.h>
#import "tlog.h"
#import "net_capture.h"

static BOOL isRelevant(NSString *s) {
    if (!s) return NO;
    return [s containsString:@"gsId"] || [s containsString:@"adiu"] ||
           [s containsString:@"risk"]  || [s containsString:@"\"data\":false"] ||
           [s containsString:@"shield"] || [s containsString:@"passport"];
}

static OSStatus (*orig_SSLRead)(SSLContextRef, void *, size_t, size_t *);
static OSStatus hook_SSLRead(SSLContextRef ctx, void *data, size_t dataLen, size_t *processed) {
    OSStatus r = orig_SSLRead(ctx, data, dataLen, processed);
    if (r != 0 || !processed || *processed < 20) return r;
    @try {
        NSString *s = [[NSString alloc] initWithBytes:data length:*processed encoding:NSUTF8StringEncoding];
        if (isRelevant(s))
            tlog(@"ssl_resp", @{@"s": s.length > 500 ? [s substringToIndex:500] : s});
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
