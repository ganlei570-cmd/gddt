#import "profile.h"
#import "tlog.h"
#import <Security/Security.h>

NSString *gIDFV = @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890";
NSString *gIDFA = @"00000000-0000-0000-0000-000000000000";
NSString *gMachine    = nil;
NSString *gDeviceName = @"iPhone";
NSString *gCarrierName = @"中国移动";
NSString *gCarrierMCC  = @"460";
NSString *gCarrierMNC  = @"00";
NSString *gCarrierISO  = @"cn";
NSString *gSysVer    = nil;
NSNumber *gDiskTotal = nil;
NSNumber *gDiskFree  = nil;
NSString *gWifiMAC          = nil;
NSString *gBootSessionUUID  = nil;
NSString *gHardwareUUID     = nil;
NSMutableSet<NSString *> *gKeychainClearSet;
NSMutableSet<NSString *> *gKeychainAllowedSet;
NSString *gUTDID_gdAmap  = nil;
NSString *gUTDID_adiuKey = nil;

static NSString *amapProfileDir(void) {
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    return [[dirs firstObject] stringByAppendingPathComponent:@"amap_profiles"];
}

void saveKeychainAllowed(void) {
    @synchronized(gKeychainAllowedSet) {
        NSArray *arr = gKeychainAllowedSet.allObjects;
        NSData *d = [NSJSONSerialization dataWithJSONObject:arr options:0 error:nil];
        NSString *path = [amapProfileDir() stringByAppendingPathComponent:@"kc_allowed.json"];
        [d writeToFile:path atomically:YES];
    }
}

static NSMutableSet<NSString *> *defaultKCSet(void) {
    return [NSMutableSet setWithObjects:
        @"com.autonavi.amap/udid",    @"com.autonavi.amap/vimsi",
        @"com.autonavi.amap/vimei",   @"com.autonavi.amap/tid",
        @"com.autonavi.amap/public_key", @"gd_amap/gd_amap",
        @"com.amap.adiu.key/com.amap.adiu.key",
        @"0.umid_v1/com.autonavi.amap",
        @"PNS_UniqueId_com.autonavi.amap/PNS_UniqueId_com.autonavi.amap",
        @"Soft/SGTMAGIC",
        @"D7CA1CE6DE13787FD151D81C8E2C8C56/D7CA1CE6DE13787FD151D81C8E2C8C56",
        nil];
}

static NSString *findActiveProfilePath(void) {
    return [amapProfileDir() stringByAppendingPathComponent:@"active.json"];
}

static NSDictionary *diskProfile(void) {
    NSString *path = findActiveProfilePath();
    if (!path) return nil;
    NSData *d = [NSData dataWithContentsOfFile:path];
    if (!d) return nil;
    return [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
}

static NSMutableSet<NSString *> *kcSetFromDict(NSDictionary *kc) {
    NSMutableSet *s = [NSMutableSet set];
    for (NSString *k in kc)
        if ([kc[k] isEqualToString:@"CLEAR"]) [s addObject:k];
    return s;
}

static void preAllowResetKeys(void) {
    for (NSString *acct in @[@"tid", @"public_key"]) {
        NSString *key = [@"com.autonavi.amap/" stringByAppendingString:acct];
        @synchronized(gKeychainAllowedSet) { [gKeychainAllowedSet addObject:key]; }
        @synchronized(gKeychainClearSet)   { [gKeychainClearSet removeObject:key]; }
    }
    saveKeychainAllowed();
    tlog(@"kc_pre_allowed", @{@"keys": @"tid,public_key"});
}

void loadProfile(void) {
    NSString *flagPath = [amapProfileDir() stringByAppendingPathComponent:@"utdid_reset.flag"];
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL didReset = [fm fileExistsAtPath:flagPath];
    if (didReset) {
        NSDictionary *q = @{
            (__bridge id)kSecClass:           (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrAccessGroup: @"Q6552JDTRL.com.autonavi.utdid",
        };
        SecItemDelete((__bridge CFDictionaryRef)q);
        for (NSString *acct in @[@"tid", @"public_key"]) {
            NSDictionary *kcQ = @{
                (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecAttrService: @"com.autonavi.amap",
                (__bridge id)kSecAttrAccount: acct,
            };
            OSStatus r = SecItemDelete((__bridge CFDictionaryRef)kcQ);
            tlog(@"kc_force_delete", @{@"key": acct, @"result": @(r)});
        }
        [fm removeItemAtPath:flagPath error:nil];
        tlog(@"utdid_reset_done", nil);
    }
    gKeychainClearSet = defaultKCSet();
    // load persisted allowed set (keys Gaode has written this session)
    gKeychainAllowedSet = [NSMutableSet set];
    NSData *ad = [NSData dataWithContentsOfFile:[amapProfileDir() stringByAppendingPathComponent:@"kc_allowed.json"]];
    if (ad) {
        NSArray *arr = [NSJSONSerialization JSONObjectWithData:ad options:0 error:nil];
        if ([arr isKindOfClass:[NSArray class]])
            [gKeychainAllowedSet addObjectsFromArray:arr];
    }
    NSDictionary *p = diskProfile();
    if (!p) {
        if (didReset) preAllowResetKeys();
        tlog(@"profile_fail", @{@"reason": @"file_not_found"});
        return;
    }
    if (p[@"idfv"])    gIDFV = p[@"idfv"];
    if (p[@"idfa"])    gIDFA = p[@"idfa"];
    if (p[@"machine"]) gMachine = p[@"machine"];
    if (p[@"carrier_name"]) gCarrierName = p[@"carrier_name"];
    if (p[@"carrier_mcc"])  gCarrierMCC  = p[@"carrier_mcc"];
    if (p[@"carrier_mnc"])  gCarrierMNC  = p[@"carrier_mnc"];
    if (p[@"carrier_iso"])  gCarrierISO  = p[@"carrier_iso"];
    if (p[@"device_name"])  gDeviceName  = p[@"device_name"];
    if (p[@"sys_ver"])    gSysVer    = p[@"sys_ver"];
    if (p[@"disk_total"]) gDiskTotal = @([p[@"disk_total"] unsignedLongLongValue]);
    if (p[@"disk_free"])  gDiskFree  = @([p[@"disk_free"]  unsignedLongLongValue]);
    if (p[@"wifi_mac"])          gWifiMAC          = p[@"wifi_mac"];
    if (p[@"boot_session_uuid"]) gBootSessionUUID  = p[@"boot_session_uuid"];
    if (p[@"hardware_uuid"])     gHardwareUUID     = p[@"hardware_uuid"];
    if (p[@"keychain"])          gKeychainClearSet = kcSetFromDict(p[@"keychain"]);
    if (p[@"utdid_gd_amap"])  gUTDID_gdAmap  = p[@"utdid_gd_amap"];
    if (p[@"utdid_adiu_key"]) gUTDID_adiuKey = p[@"utdid_adiu_key"];
    if (didReset) preAllowResetKeys();
    tlog(@"profile_ok", @{@"idfv_prefix": [gIDFV substringToIndex:MIN(8u, gIDFV.length)]});
}
