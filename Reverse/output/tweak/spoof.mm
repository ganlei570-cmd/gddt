#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
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

static BOOL isAmapKey(NSString *key) {
    return [key containsString:@"amap"] || [key containsString:@"autonavi"];
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
    MSHookFunction((void *)SecItemCopyMatching, (void *)hook_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
    MSHookFunction((void *)SecItemAdd,    (void *)hook_SecItemAdd,    (void **)&orig_SecItemAdd);
    MSHookFunction((void *)SecItemUpdate, (void *)hook_SecItemUpdate, (void **)&orig_SecItemUpdate);
    dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOW);
    void *fnCN = dlsym(RTLD_DEFAULT, "CNCopyCurrentNetworkInfo");
    if (fnCN) MSHookFunction(fnCN, (void *)hook_CNCopyCurrentNetworkInfo, (void **)&orig_CNCopyCurrentNetworkInfo);
    tlog(@"spoof_installed", nil);
}
