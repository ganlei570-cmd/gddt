#import <Foundation/Foundation.h>
#import "tlog.h"
#import <sys/sysctl.h>
#import <CoreFoundation/CoreFoundation.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <dlfcn.h>
#import <mach/mach.h>
#include <signal.h>
#include <unistd.h>
#import <substrate.h>
#import <objc/runtime.h>
#import "bypass.h"
#import "profile.h"

static const char * const kJailPaths[] = {
    "/var/jb", "/private/var/jb",
    "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
    "/Library/MobileSubstrate", "/usr/sbin/sshd", "/usr/bin/ssh",
    "/etc/apt", "/private/var/lib/apt", "/private/var/stash",
    "/usr/lib/TweakInject", "/usr/lib/ellekit", "/usr/lib/substrate",
    "/private/preboot", "systemhook", "ElleKit", "frida", "FridaGadget",
    "cynject", "substitute", NULL
};
static const char * const kInjKw[] = {
    "frida", "cynject", NULL
};

static const char * const kHideDylibs[] = {
    "AmapNewDevice", "ElleKit", "ellekit", "TweakInject", "tweakinject",
    "systemhook", "cynject", "frida", "substrate", "MobileSubstrate",
    "cycript", NULL
};

static BOOL isJailPath(const char *p) {
    if (!p) return NO;
    for (int i = 0; kJailPaths[i]; i++)
        if (strstr(p, kJailPaths[i])) return YES;
    return NO;
}
static BOOL isInjDylib(const char *n) {
    if (!n) return NO;
    for (int i = 0; kInjKw[i]; i++)
        if (strcasestr(n, kInjKw[i])) return YES;
    return NO;
}

static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int hook_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    return (req == 31) ? 0 : orig_ptrace(req, pid, addr, data);
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hook_sysctl(int *mib, u_int nl, void *old, size_t *osz, void *n, size_t nsz) {
    int r = orig_sysctl(mib, nl, old, osz, n, nsz);
    if (r == 0 && nl >= 2 && mib[0] == 1 && mib[1] == 14 && old)
        *(uint32_t *)((char *)old + 32) &= ~0x800u;
    return r;
}

static uint32_t (*orig_dyld_count)(void);
static const char *(*orig_dyld_name)(uint32_t);

static BOOL shouldHideDylib(const char *name) {
    if (!name) return NO;
    for (int i = 0; kHideDylibs[i]; i++)
        if (strcasestr(name, kHideDylibs[i])) return YES;
    return NO;
}

static uint32_t hook_dyld_count(void) {
    uint32_t total = orig_dyld_count();
    uint32_t hidden = 0;
    for (uint32_t i = 0; i < total; i++)
        if (shouldHideDylib(orig_dyld_name(i))) hidden++;
    return total - hidden;
}

static const char *hook_dyld_name(uint32_t idx) {
    uint32_t total = orig_dyld_count();
    uint32_t visible = 0;
    for (uint32_t i = 0; i < total; i++) {
        const char *name = orig_dyld_name(i);
        if (shouldHideDylib(name)) continue;
        if (visible == idx) return name;
        visible++;
    }
    return orig_dyld_name(idx);
}

static int (*orig_connect)(int, const struct sockaddr *, socklen_t);
static int hook_connect(int fd, const struct sockaddr *sa, socklen_t sl) {
    if (sa && sa->sa_family == AF_INET) {
        uint16_t port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
        if (port == 27042 || port == 27043) return -1;
    }
    return orig_connect(fd, sa, sl);
}

static int (*orig_access)(const char *, int);
static int hook_access(const char *p, int m) { return isJailPath(p) ? -1 : orig_access(p, m); }

static FILE *(*orig_fopen)(const char *, const char *);
static FILE *hook_fopen(const char *p, const char *m) { return isJailPath(p) ? NULL : orig_fopen(p, m); }

static int (*orig_stat)(const char *, struct stat *);
static int hook_stat(const char *p, struct stat *s) { return isJailPath(p) ? -1 : orig_stat(p, s); }

static char *(*orig_getenv)(const char *);
static char *hook_getenv(const char *k) {
    if (k && (!strcmp(k, "DYLD_INSERT_LIBRARIES") || !strcmp(k, "DYLD_LIBRARY_PATH")))
        return NULL;
    return orig_getenv(k);
}

static FILE *(*orig_popen)(const char *, const char *);
static FILE *hook_popen(const char *c, const char *m) { return NULL; }
static int (*orig_system)(const char *);
static int hook_system(const char *c) { return 0; }

static void *(*orig_dlopen)(const char *, int);
static void *hook_dlopen(const char *p, int f) { return isInjDylib(p) ? NULL : orig_dlopen(p, f); }

static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static int hook_sysctlbyname(const char *n, void *o, size_t *sz, void *ne, size_t nsz) {
    if (n && strstr(n, "kern.proc.pid")) return -1;
    int r = orig_sysctlbyname(n, o, sz, ne, nsz);
    if (r != 0 || !o || !sz || !n) return r;
    if (gMachine && (strcmp(n, "hw.machine") == 0 || strcmp(n, "hw.model") == 0)) {
        const char *m = [gMachine UTF8String];
        strlcpy((char *)o, m, *sz);
        *sz = strlen(m) + 1;
    } else if (gBootSessionUUID && strcmp(n, "kern.bootsessionuuid") == 0) {
        const char *u = [gBootSessionUUID UTF8String];
        strlcpy((char *)o, u, *sz);
        *sz = strlen(u) + 1;
    } else if (gHardwareUUID && (strcmp(n, "kern.hostuuid") == 0 || strcmp(n, "hw.uuid") == 0)) {
        const char *u = [gHardwareUUID UTF8String];
        strlcpy((char *)o, u, *sz);
        *sz = strlen(u) + 1;
    }
    return r;
}

static CFTypeRef (*orig_IORegCreateCFProp)(mach_port_t, CFStringRef, CFAllocatorRef, uint32_t);
static CFTypeRef hook_IORegCreateCFProp(mach_port_t entry, CFStringRef key, CFAllocatorRef alloc, uint32_t opts) {
    if (gHardwareUUID && key && CFStringCompare(key, CFSTR("IOPlatformUUID"), 0) == kCFCompareEqualTo)
        return CFStringCreateCopy(alloc ?: kCFAllocatorDefault, (__bridge CFStringRef)gHardwareUUID);
    return orig_IORegCreateCFProp(entry, key, alloc, opts);
}

#if defined(__arm64e__)
#import <ptrauth.h>
#define _STRIP(p) ptrauth_strip((void*)(p), ptrauth_key_function_pointer)
#else
#define _STRIP(p) ((void*)(p))
#endif
#define MH(sym, hook, orig) do { void *_f=dlsym(RTLD_DEFAULT,sym); if(_f) MSHookFunction(_STRIP(_f),(void*)(hook),(void**)(orig)); } while(0)

static kern_return_t (*orig_task_info)(task_name_t, task_flavor_t, task_info_t, mach_msg_type_number_t *);
static kern_return_t hook_task_info(task_name_t t, task_flavor_t f, task_info_t info, mach_msg_type_number_t *cnt) {
    orig_task_info(t, f, info, cnt);
    return KERN_SUCCESS;
}

static kern_return_t (*orig_task_exc_ports)(task_t, exception_mask_t, exception_mask_array_t, mach_msg_type_number_t *, exception_handler_array_t, exception_behavior_array_t, exception_flavor_array_t);
static kern_return_t hook_task_exc_ports(task_t t, exception_mask_t m, exception_mask_array_t masks, mach_msg_type_number_t *cnt, exception_handler_array_t h, exception_behavior_array_t b, exception_flavor_array_t flv) {
    if (cnt) *cnt = 0;
    return KERN_SUCCESS;
}

static void (*orig_exit)(int);
static void hook_exit(int code) { tlog(@"exit_blocked", @{@"code": @(code)}); }

static void (*orig__exit)(int);
static void hook__exit(int code) { tlog(@"_exit_blocked", @{@"code": @(code)}); }

static void (*orig_abort)(void);
static void hook_abort(void) { tlog(@"abort_blocked", nil); }

static int (*orig_kill)(pid_t, int);
static int hook_kill(pid_t pid, int sig) {
    if (pid == getpid() && (sig == SIGKILL || sig == SIGTERM)) {
        tlog(@"kill_blocked", @{@"sig": @(sig)});
        return 0;
    }
    return orig_kill(pid, sig);
}


// ── DTHbalSe 风控 JSON 拦截：解析层改 data:false → data:true（无时机问题）──────────────
static id (*orig_JSONObject)(Class, SEL, NSData *, NSJSONReadingOptions, NSError **);
static id hook_JSONObject(Class cls, SEL cmd, NSData *data, NSJSONReadingOptions opts, NSError **err) {
    id result = orig_JSONObject(cls, cmd, data, opts, err);
    if (![result isKindOfClass:[NSDictionary class]]) return result;
    NSDictionary *d = result;
    if (d[@"gsId"] && [d[@"result"] isEqual:@YES] && [d[@"data"] isEqual:@NO]) {
        NSMutableDictionary *m = [d mutableCopy];
        m[@"data"] = @YES;
        tlog(@"shield_patched", nil);
        return m;
    }
    return result;
}

// ── DTHbalSe 风控上报拦截：透传 amapstream/upload，把响应 "data":false → "data":true ────
@interface AmapShieldProtocol : NSURLProtocol <NSURLSessionDataDelegate>
@property NSMutableData *buf;
@property NSURLSessionDataTask *fwd;
@property NSURLSession *sess;
@end
@implementation AmapShieldProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)r {
    if ([NSURLProtocol propertyForKey:@"_asp" inRequest:r]) return NO;
    NSString *p = r.URL.path;
    return p && ([p containsString:@"/shield/amapstream/upload"] || [p containsString:@"/shield/nest/updatable/v1/log"]);
}
+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)r { return r; }
- (void)startLoading {
    NSMutableURLRequest *mr = [self.request mutableCopy];
    [NSURLProtocol setProperty:@1 forKey:@"_asp" inRequest:mr];
    NSURLSessionConfiguration *c = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    c.protocolClasses = @[];
    self.buf = [NSMutableData data];
    self.sess = [NSURLSession sessionWithConfiguration:c delegate:self delegateQueue:nil];
    self.fwd = [self.sess dataTaskWithRequest:mr];
    [self.fwd resume];
}
- (void)stopLoading { [self.fwd cancel]; [self.sess invalidateAndCancel]; }
- (void)URLSession:(NSURLSession *)s dataTask:(NSURLSessionDataTask *)t didReceiveResponse:(NSURLResponse *)r completionHandler:(void(^)(NSURLSessionResponseDisposition))h {
    [self.client URLProtocol:self didReceiveResponse:r cacheStoragePolicy:NSURLCacheStorageNotAllowed]; h(NSURLSessionResponseAllow);
}
- (void)URLSession:(NSURLSession *)s dataTask:(NSURLSessionDataTask *)t didReceiveData:(NSData *)d { [self.buf appendData:d]; }
- (void)URLSession:(NSURLSession *)s task:(NSURLSessionTask *)t didCompleteWithError:(NSError *)e {
    NSData *out = self.buf;
    if (!e) {
        NSString *str = [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding];
        if (str && [str containsString:@"\"data\":false"]) {
            NSData *d = [[str stringByReplacingOccurrencesOfString:@"\"data\":false" withString:@"\"data\":true"] dataUsingEncoding:NSUTF8StringEncoding];
            if (d) { out = d; tlog(@"shield_patched", nil); }
        }
    }
    [s invalidateAndCancel];
    if (e) { [self.client URLProtocol:self didFailWithError:e]; return; }
    [self.client URLProtocol:self didLoadData:out];
    [self.client URLProtocolDidFinishLoading:self];
}
@end

static void injectShield(NSURLSessionConfiguration *c) {
    if (!c || [c.protocolClasses containsObject:[AmapShieldProtocol class]]) return;
    NSMutableArray *p = [[NSMutableArray alloc] initWithObjects:[AmapShieldProtocol class], nil];
    if (c.protocolClasses) [p addObjectsFromArray:c.protocolClasses];
    c.protocolClasses = p;
}
static id (*orig_newSess)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
static id hook_newSess(id s, SEL c, NSURLSessionConfiguration *cfg, id d, NSOperationQueue *q) {
    injectShield(cfg); return orig_newSess(s, c, cfg, d, q);
}

// ── Cookie 保护：阻止 DTHbalSe 批量清除 session（掉登录根因）─────────────
static void (*orig_deleteCookie)(id, SEL, id);
static void hook_deleteCookie(id self, SEL _cmd, id cookie) {
    NSHTTPCookie *c = (NSHTTPCookie *)cookie;
    NSString *domain = c.domain ?: @"";
    if ([domain hasSuffix:@".amap.com"] || [domain hasSuffix:@".alipay.com"] ||
        [domain isEqualToString:@"amap.com"] || [domain isEqualToString:@"alipay.com"]) {
        tlog(@"cookie_protected", @{@"domain": domain, @"name": c.name ?: @""});
        return;
    }
    orig_deleteCookie(self, _cmd, cookie);
}

static void hookAntiDebug(void) {
    MH("ptrace",  hook_ptrace,  &orig_ptrace);
    MH("sysctl",  hook_sysctl,  &orig_sysctl);
    MH("_dyld_image_count",    hook_dyld_count, &orig_dyld_count);
    MH("_dyld_get_image_name", hook_dyld_name,  &orig_dyld_name);
    MH("sysctlbyname", hook_sysctlbyname, &orig_sysctlbyname);
    MH("task_info", hook_task_info, &orig_task_info);
    MH("task_get_exception_ports", hook_task_exc_ports, &orig_task_exc_ports);
    MH("exit",  hook_exit,  &orig_exit);
    MH("_exit", hook__exit, &orig__exit);
    MH("abort", hook_abort, &orig_abort);
    MH("kill",  hook_kill,  &orig_kill);
}

static void hookEnvDetect(void) {
    MH("connect", hook_connect, &orig_connect);
    MH("access",  hook_access,  &orig_access);
    MH("fopen",   hook_fopen,   &orig_fopen);
    void *sfn = dlsym(RTLD_DEFAULT, "stat64") ?: dlsym(RTLD_DEFAULT, "stat");
    if (sfn) MSHookFunction(sfn, (void *)hook_stat, (void **)&orig_stat);
    MH("getenv",  hook_getenv,  &orig_getenv);
    MH("popen",   hook_popen,   &orig_popen);
    MH("system",  hook_system,  &orig_system);
    MH("dlopen",  hook_dlopen,  &orig_dlopen);
}

void installBypassHooks(void) {
    hookAntiDebug();
    hookEnvDetect();
    dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW);
    MH("IORegistryEntryCreateCFProperty", hook_IORegCreateCFProp, &orig_IORegCreateCFProp);
    MSHookMessageEx(
        NSClassFromString(@"NSHTTPCookieStorage"),
        @selector(deleteCookie:),
        (IMP)hook_deleteCookie,
        (IMP *)&orig_deleteCookie);
    MSHookMessageEx(
        object_getClass(NSClassFromString(@"NSJSONSerialization")),
        @selector(JSONObjectWithData:options:error:),
        (IMP)hook_JSONObject,
        (IMP *)&orig_JSONObject);
    [NSURLProtocol registerClass:[AmapShieldProtocol class]];
    MSHookMessageEx(
        object_getClass(NSClassFromString(@"NSURLSession")),
        @selector(sessionWithConfiguration:delegate:delegateQueue:),
        (IMP)hook_newSess,
        (IMP *)&orig_newSess);
    tlog(@"bypass_installed", nil);
}
