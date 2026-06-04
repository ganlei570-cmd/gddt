#import "profile.h"
#import "tlog.h"

NSString *gIDFV = @"A1B2C3D4-E5F6-7890-ABCD-EF1234567890";
NSString *gIDFA = @"00000000-0000-0000-0000-000000000000";
NSString *gMachine    = nil;
NSString *gCarrierName = @"中国移动";
NSString *gCarrierMCC  = @"460";
NSString *gCarrierMNC  = @"00";
NSString *gCarrierISO  = @"cn";
NSMutableSet<NSString *> *gKeychainClearSet;

static NSMutableSet<NSString *> *defaultKCSet(void) {
    return [NSMutableSet setWithObjects:
        @"com.autonavi.amap/udid",    @"com.autonavi.amap/vimsi",
        @"com.autonavi.amap/vimei",   @"com.autonavi.amap/tid",
        @"com.autonavi.amap/public_key", @"gd_amap/gd_amap",
        @"com.amap.adiu.key/com.amap.adiu.key",
        @"0.umid_v1/com.autonavi.amap",
        @"PNS_UniqueId_com.autonavi.amap/PNS_UniqueId_com.autonavi.amap", nil];
}

static NSString *findActiveProfilePath(void) {
    return @"/var/mobile/Documents/amap_profiles/active.json";
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


void loadProfile(void) {
    gKeychainClearSet = defaultKCSet();
    NSDictionary *p = diskProfile();
    if (!p) {
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
    if (p[@"keychain"])     gKeychainClearSet = kcSetFromDict(p[@"keychain"]);
    tlog(@"profile_ok", @{@"idfv_prefix": [gIDFV substringToIndex:MIN(8u, gIDFV.length)]});
}
