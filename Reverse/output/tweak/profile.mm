#import "profile.h"

NSString *gIDFV = @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890";
NSString *gIDFA = @"00000000-0000-0000-0000-000000000000";
NSSet<NSString *> *gKeychainClearSet;
NSSet<NSString *> *gPrefClearSet;

static NSSet<NSString *> *defaultKCSet(void) {
    return [NSSet setWithObjects:
        @"com.autonavi.amap/udid",    @"com.autonavi.amap/vimsi",
        @"com.autonavi.amap/vimei",   @"com.autonavi.amap/tid",
        @"com.autonavi.amap/public_key", @"gd_amap/gd_amap",
        @"com.amap.adiu.key/com.amap.adiu.key",
        @"0.umid_v1/com.autonavi.amap",
        @"PNS_UniqueId_com.autonavi.amap/PNS_UniqueId_com.autonavi.amap", nil];
}

static NSSet<NSString *> *defaultPrefSet(void) {
    return [NSSet setWithObjects:
        @"__AMAP_APP_FIRST__", @"appInitMd5",
        @"login_credit", @"ATAuthSDK_POP_com.autonavi.amap", nil];
}

static NSString *findActiveProfilePath(void) {
    NSString *base = @"/var/mobile/Containers/Data/Application";
    NSArray *uuids = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:base error:nil];
    for (NSString *uuid in uuids) {
        NSString *meta = [base stringByAppendingFormat:
            @"/%@/.com.apple.mobile_container_manager.metadata.plist", uuid];
        NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:meta];
        if ([@"com.amap.newmachine" isEqualToString:d[@"MCMMetadataIdentifier"]]) {
            return [base stringByAppendingFormat:
                @"/%@/Documents/amap_profiles/active.json", uuid];
        }
    }
    return nil;
}

static NSDictionary *diskProfile(void) {
    NSString *path = findActiveProfilePath();
    if (!path) return nil;
    NSData *d = [NSData dataWithContentsOfFile:path];
    if (!d) return nil;
    return [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
}

static NSSet<NSString *> *kcSetFromDict(NSDictionary *kc) {
    NSMutableSet *s = [NSMutableSet set];
    for (NSString *k in kc)
        if ([kc[k] isEqualToString:@"CLEAR"]) [s addObject:k];
    return [s copy];
}

static NSSet<NSString *> *prefSetFromDict(NSDictionary *ud) {
    NSMutableSet *s = [NSMutableSet set];
    for (NSString *k in ud)
        if (!ud[k] || ud[k] == [NSNull null]) [s addObject:k];
    return [s copy];
}

void loadProfile(void) {
    gKeychainClearSet = defaultKCSet();
    gPrefClearSet = defaultPrefSet();
    NSDictionary *p = diskProfile();
    if (!p) return;
    if (p[@"idfv"]) gIDFV = p[@"idfv"];
    if (p[@"idfa"]) gIDFA = p[@"idfa"];
    if (p[@"keychain"]) gKeychainClearSet = kcSetFromDict(p[@"keychain"]);
    if (p[@"userdefaults"]) gPrefClearSet = prefSetFromDict(p[@"userdefaults"]);
}
