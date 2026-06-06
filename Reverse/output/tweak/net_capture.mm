#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <substrate.h>
#import "tlog.h"
#import "net_capture.h"

static BOOL isAmapUrl(NSString *u) {
    if (!u) return NO;
    return [u containsString:@"shield"] || [u containsString:@"passport.amap"] ||
           [u containsString:@"adiu"] || [u containsString:@"m5-x"] || [u containsString:@"m5.amap"];
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
        if (isAmapUrl(u)) {
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
        if (isAmapUrl(u))
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

static void (*orig_task_resume)(id, SEL);
static void hook_task_resume(id self, SEL cmd) {
    @try {
        NSURLSessionTask *t = (NSURLSessionTask *)self;
        NSString *u = (t.currentRequest ?: t.originalRequest).URL.absoluteString;
        if (isAmapUrl(u))
            tlog(@"net_url", @{@"u": u.length > 150 ? [u substringToIndex:150] : u});
    } @catch(id e) {}
    orig_task_resume(self, cmd);
}

void installNetCaptureHooks(void) {
    MSHookMessageEx(
        object_getClass(NSClassFromString(@"NSURLSession")),
        @selector(sessionWithConfiguration:delegate:delegateQueue:),
        (IMP)hook_newSess,
        (IMP *)&orig_newSess);
    MSHookMessageEx(
        NSClassFromString(@"NSURLSessionTask"),
        @selector(resume),
        (IMP)hook_task_resume,
        (IMP *)&orig_task_resume);
}
