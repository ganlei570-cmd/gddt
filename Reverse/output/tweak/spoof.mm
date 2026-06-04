#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
#import <sys/mount.h>
#import <sys/statvfs.h>
#import <dlfcn.h>
#import <substrate.h>
#import "profile.h"
#import "spoof.h"
#import "tlog.h"

static NSString *kcQueryKey(CFDictionaryRef q) {
    CFTypeRef svc = CFDictionaryGetValue(q, kSecAttrService);
    CFTypeRef acc = CFDictionaryGetValue(q, kSecAttrAccount);
    if (!svc || !acc) return nil;
    if (CFGetTypeID(svc) != CFStringGetTypeID() || CFGetTypeID(acc) != CFStringGetTypeID()) return nil;
    return [(__bridge NSString *)svc stringByAppendingFormat:@"/%@", (__bridge NSString *)acc];
}

static BOOL gUTDIDGroupUnlocked = NO;

static BOOL isAmapKey(NSString *key) {
    if (!key) return NO;
    if ([key containsString:@"amap"] || [key containsString:@"autonavi"]) return YES;
    if ([key hasPrefix:@"com.alipay.alisecx"] || [key hasPrefix:@"com.alipay.asssecuresdk"]) return YES;
    if ([key hasPrefix:@"0.umid_v1/"] || [key hasPrefix:@"0.apdid_v1/"]) return YES;
    if ([key hasPrefix:@"Soft/"] || [key hasPrefix:@"D7CA1CE6"]) return YES;
    return NO;
}

static BOOL isUTDIDGroup(CFDictionaryRef q) {
    CFTypeRef grp = CFDictionaryGetValue(q, kSecAttrAccessGroup);
    if (!grp || CFGetTypeID(grp) != CFStringGetTypeID()) return NO;
    return [(__bridge NSString *)grp containsString:@"com.autonavi.utdid"];
}

static BOOL shouldBlockKey(NSString *key) {
    if (!key) return NO;
    // always block keys in the explicit clear set (device identity keys)
    if ([gKeychainClearSet containsObject:key]) return YES;
    // block all amap/autonavi keys unless Gaode has written them this session
    if (isAmapKey(key)) {
        BOOL allowed;
        @synchronized(gKeychainAllowedSet) { allowed = [gKeychainAllowedSet containsObject:key]; }
        return !allowed;
    }
    return NO;
}

static int (*orig_statfs)(const char *, struct statfs *) = NULL;
static int hook_statfs(const char *path, struct statfs *buf) {
    int r = orig_statfs(path, buf);
    if (r != 0 || !gDiskTotal || !gDiskFree || buf->f_bsize == 0) return r;
    uint64_t bs = (uint64_t)buf->f_bsize;
    buf->f_blocks = (typeof(buf->f_blocks))([gDiskTotal unsignedLongLongValue] / bs);
    buf->f_bfree  = (typeof(buf->f_bfree)) ([gDiskFree  unsignedLongLongValue] / bs);
    buf->f_bavail = buf->f_bfree;
    return r;
}

static int (*orig_statvfs)(const char *, struct statvfs *) = NULL;
static int hook_statvfs(const char *path, struct statvfs *buf) {
    int r = orig_statvfs(path, buf);
    if (r != 0 || !gDiskTotal || !gDiskFree) return r;
    unsigned long fs = buf->f_frsize > 0 ? buf->f_frsize : buf->f_bsize;
    if (fs == 0) return r;
    buf->f_blocks = (typeof(buf->f_blocks))([gDiskTotal unsignedLongLongValue] / fs);
    buf->f_bfree  = (typeof(buf->f_bfree)) ([gDiskFree  unsignedLongLongValue] / fs);
    buf->f_bavail = buf->f_bfree;
    return r;
}

static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef) = NULL;
static CFDictionaryRef hook_CNCopyCurrentNetworkInfo(CFStringRef iface) {
    CFDictionaryRef orig = orig_CNCopyCurrentNetworkInfo(iface);
    if (!gWifiMAC || !orig) return orig;
    NSMutableDictionary *d = [(__bridge NSDictionary *)orig mutableCopy];
    CFRelease(orig);
    d[@"BSSID"] = gWifiMAC;
    return (CFDictionaryRef)CFBridgingRetain(d);
}

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *result) {
    if (isUTDIDGroup(q) && !gUTDIDGroupUnlocked) {
        tlog(@"kc_utdid_blocked", nil);
        if (result) *result = NULL;
        return errSecItemNotFound;
    }
    NSString *key = kcQueryKey(q);
    if (shouldBlockKey(key)) {
        tlog(@"kc_blocked", @{@"key": key ?: @"nil"});
        if (result) *result = NULL;
        return errSecItemNotFound;
    }
    return orig_SecItemCopyMatching(q, result);
}

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SecItemAdd(CFDictionaryRef attrs, CFTypeRef *result) {
    if (isUTDIDGroup(attrs)) {
        OSStatus r = orig_SecItemAdd(attrs, result);
        if (r == errSecSuccess) { gUTDIDGroupUnlocked = YES; tlog(@"kc_utdid_written", nil); }
        return r;
    }
    NSString *key = kcQueryKey(attrs);
    OSStatus r = orig_SecItemAdd(attrs, result);
    if (r == errSecSuccess && key && isAmapKey(key)) {
        @synchronized(gKeychainAllowedSet) { [gKeychainAllowedSet addObject:key]; }
        @synchronized(gKeychainClearSet)   { [gKeychainClearSet removeObject:key]; }
        saveKeychainAllowed();
        tlog(@"kc_written", @{@"key": key});
    }
    return r;
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus hook_SecItemUpdate(CFDictionaryRef q, CFDictionaryRef attrs) {
    if (isUTDIDGroup(q)) {
        OSStatus r = orig_SecItemUpdate(q, attrs);
        if (r == errSecSuccess) { gUTDIDGroupUnlocked = YES; tlog(@"kc_utdid_updated", nil); }
        return r;
    }
    NSString *key = kcQueryKey(q);
    OSStatus r = orig_SecItemUpdate(q, attrs);
    if (r == errSecSuccess && key && isAmapKey(key)) {
        @synchronized(gKeychainAllowedSet) { [gKeychainAllowedSet addObject:key]; }
        @synchronized(gKeychainClearSet)   { [gKeychainClearSet removeObject:key]; }
        saveKeychainAllowed();
        tlog(@"kc_updated", @{@"key": key});
    }
    return r;
}

void installSpoofHooks(void) {
    MSHookFunction((void *)statfs,  (void *)hook_statfs,  (void **)&orig_statfs);
    MSHookFunction((void *)statvfs, (void *)hook_statvfs, (void **)&orig_statvfs);
    MSHookFunction((void *)SecItemCopyMatching, (void *)hook_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
    MSHookFunction((void *)SecItemAdd,    (void *)hook_SecItemAdd,    (void **)&orig_SecItemAdd);
    MSHookFunction((void *)SecItemUpdate, (void *)hook_SecItemUpdate, (void **)&orig_SecItemUpdate);
    dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOW);
    void *fnCN = dlsym(RTLD_DEFAULT, "CNCopyCurrentNetworkInfo");
    if (fnCN) MSHookFunction(fnCN, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
    tlog(@"spoof_installed", nil);
}
