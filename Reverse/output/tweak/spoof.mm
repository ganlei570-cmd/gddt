#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CoreFoundation/CoreFoundation.h>
#import <dlfcn.h>
#import <substrate.h>
#import "profile.h"
#import "spoof.h"

static NSString *kcQueryKey(CFDictionaryRef q) {
    CFStringRef svc = CFDictionaryGetValue(q, kSecAttrService);
    CFStringRef acc = CFDictionaryGetValue(q, kSecAttrAccount);
    if (!svc || !acc) return nil;
    return [(__bridge NSString *)svc stringByAppendingFormat:@"/%@", (__bridge NSString *)acc];
}

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *result) {
    NSString *key = kcQueryKey(q);
    if (key && [gKeychainClearSet containsObject:key]) {
        if (result) *result = NULL;
        return errSecItemNotFound;
    }
    return orig_SecItemCopyMatching(q, result);
}

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus hook_SecItemAdd(CFDictionaryRef attrs, CFTypeRef *result) {
    return orig_SecItemAdd(attrs, result);
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus hook_SecItemUpdate(CFDictionaryRef q, CFDictionaryRef attrs) {
    return orig_SecItemUpdate(q, attrs);
}

static CFTypeRef (*orig_CFPrefsCopy)(CFStringRef, CFStringRef);
static CFTypeRef hook_CFPrefsCopy(CFStringRef key, CFStringRef appID) {
    if (key && [gPrefClearSet containsObject:(__bridge NSString *)key])
        return NULL;
    return orig_CFPrefsCopy(key, appID);
}

void installSpoofHooks(void) {
    MSHookFunction((void *)SecItemCopyMatching, (void *)hook_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
    MSHookFunction((void *)SecItemAdd,    (void *)hook_SecItemAdd,    (void **)&orig_SecItemAdd);
    MSHookFunction((void *)SecItemUpdate, (void *)hook_SecItemUpdate, (void **)&orig_SecItemUpdate);
    void *fn = dlsym(RTLD_DEFAULT, "CFPreferencesCopyAppValue")
             ?: dlsym(RTLD_DEFAULT, "CFPreferencesGetAppValue");
    if (fn) MSHookFunction(fn, (void *)hook_CFPrefsCopy, (void **)&orig_CFPrefsCopy);
}
