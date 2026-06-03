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

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *result) {
    NSString *key = kcQueryKey(q);
    if (key) {
        BOOL blocked;
        @synchronized(gKeychainClearSet) { blocked = [gKeychainClearSet containsObject:key]; }
        if (blocked) {
            tlog(@"kc_blocked", @{@"key": key});
            if (result) *result = NULL;
            return errSecItemNotFound;
        }
    }
    return orig_SecItemCopyMatching(q, result);
}

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SecItemAdd(CFDictionaryRef attrs, CFTypeRef *result) {
    NSString *key = kcQueryKey(attrs);
    OSStatus r = orig_SecItemAdd(attrs, result);
    if (r == errSecSuccess && key) {
        @synchronized(gKeychainClearSet) { [gKeychainClearSet removeObject:key]; }
        tlog(@"kc_written", @{@"key": key});
    }
    return r;
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus hook_SecItemUpdate(CFDictionaryRef q, CFDictionaryRef attrs) {
    NSString *key = kcQueryKey(q);
    OSStatus r = orig_SecItemUpdate(q, attrs);
    if (r == errSecSuccess && key) {
        @synchronized(gKeychainClearSet) { [gKeychainClearSet removeObject:key]; }
        tlog(@"kc_updated", @{@"key": key});
    }
    return r;
}

void installSpoofHooks(void) {
    MSHookFunction((void *)SecItemCopyMatching, (void *)hook_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
    MSHookFunction((void *)SecItemAdd,    (void *)hook_SecItemAdd,    (void **)&orig_SecItemAdd);
    MSHookFunction((void *)SecItemUpdate, (void *)hook_SecItemUpdate, (void **)&orig_SecItemUpdate);
    tlog(@"spoof_installed", nil);
}
