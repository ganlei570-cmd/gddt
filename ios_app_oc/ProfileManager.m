#import "ProfileManager.h"

static NSString *const kDir    = @"/var/mobile/Documents/amap_profiles";
static NSString *const kActive = @"/var/mobile/Documents/amap_profiles/active.json";

// keychain 条目："service/account" 格式，与 tweak profile.mm 匹配
static NSArray<NSString *> *kcKeys(void) {
    return @[
        @"com.autonavi.amap/udid",
        @"com.autonavi.amap/vimsi",
        @"com.autonavi.amap/vimei",
        @"com.autonavi.amap/tid",
        @"com.autonavi.amap/public_key",
        @"gd_amap/gd_amap",
        @"com.amap.adiu.key/com.amap.adiu.key",
        @"0.umid_v1/com.autonavi.amap",
        @"PNS_UniqueId_com.autonavi.amap/PNS_UniqueId_com.autonavi.amap",
    ];
}

@implementation ProfileManager

+ (instancetype)shared {
    static ProfileManager *s; static dispatch_once_t t;
    dispatch_once(&t, ^{ s = [self new]; [s reload]; });
    return s;
}

- (void)reload {
    NSData *d = [NSData dataWithContentsOfFile:kActive];
    if (!d) return;
    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
    self.activeIdfv = j[@"idfv"] ?: @"";
}

// ── 生成新 profile (格式与 spoof.js BUILTIN_PROFILE 完全一致) ─────────────
- (NSDictionary *)generateProfile {
    NSMutableDictionary *kc = [NSMutableDictionary dictionary];
    for (NSString *k in kcKeys()) kc[k] = @"CLEAR";

    // NSNull → JSON null，tweak 读到 null 即清除该 preference
    NSMutableDictionary *ud = [NSMutableDictionary dictionary];
    for (NSString *k in @[@"__AMAP_APP_FIRST__", @"appInitMd5",
                          @"login_credit", @"ATAuthSDK_POP_com.autonavi.amap"])
        ud[k] = [NSNull null];

    return @{
        @"idfv": [NSUUID UUID].UUIDString.uppercaseString,
        @"idfa": @"00000000-0000-0000-0000-000000000000",
        @"keychain":      kc,
        @"userdefaults":  ud,
    };
}

// ── 写入 active.json ──────────────────────────────────────────────────────
- (BOOL)saveActive:(NSDictionary *)profile error:(NSError **)error {
    [[NSFileManager defaultManager]
        createDirectoryAtPath:kDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSData *data = [NSJSONSerialization dataWithJSONObject:profile
                    options:NSJSONWritingPrettyPrinted error:error];
    if (!data) return NO;
    BOOL ok = [data writeToFile:kActive options:NSDataWritingAtomic error:error];
    if (ok) self.activeIdfv = profile[@"idfv"] ?: @"";
    return ok;
}

- (BOOL)newMachineWithError:(NSError **)error {
    return [self saveActive:[self generateProfile] error:error];
}

- (BOOL)clearKeychainWithError:(NSError **)error {
    NSData *d = [NSData dataWithContentsOfFile:kActive];
    NSMutableDictionary *p = d
        ? [[NSJSONSerialization JSONObjectWithData:d options:NSJSONReadingMutableContainers error:nil] mutableCopy]
        : [[self generateProfile] mutableCopy];
    if (!p) p = [[self generateProfile] mutableCopy];
    NSMutableDictionary *kc = [NSMutableDictionary dictionary];
    for (NSString *k in kcKeys()) kc[k] = @"CLEAR";
    p[@"keychain"] = kc;
    return [self saveActive:p error:error];
}

// ── 备份列表 ──────────────────────────────────────────────────────────────
- (NSArray<NSDictionary *> *)listBackups {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *result = [NSMutableArray array];
    for (NSString *f in [fm contentsOfDirectoryAtPath:kDir error:nil]) {
        if (![f hasPrefix:@"高德地图_"] || ![f hasSuffix:@".json"]) continue;
        NSString *full = [kDir stringByAppendingPathComponent:f];
        NSDictionary *attr = [fm attributesOfItemAtPath:full error:nil];
        NSData *d = [NSData dataWithContentsOfFile:full];
        NSString *idfv = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil][@"idfv"] ?: @"" : @"";
        NSDateFormatter *fmt = [NSDateFormatter new];
        fmt.dateFormat = @"MM-dd HH:mm";
        [result addObject:@{
            @"name": [f substringToIndex:f.length - 5],
            @"path": full,
            @"idfv": idfv.length > 18 ? [idfv substringToIndex:18] : idfv,
            @"date": [fmt stringFromDate:attr[NSFileCreationDate] ?: [NSDate date]],
            @"size": @([attr[NSFileSize] unsignedLongLongValue] / 1024),
        }];
    }
    return [result sortedArrayUsingComparator:^(id a, id b) {
        return [b[@"date"] compare:a[@"date"]];
    }];
}

- (BOOL)backupWithError:(NSError **)error {
    NSData *d = [NSData dataWithContentsOfFile:kActive];
    if (!d) {
        if (error) *error = [NSError errorWithDomain:@"PM" code:1
            userInfo:@{NSLocalizedDescriptionKey: @"无 active 档案，请先执行一键新机"}];
        return NO;
    }
    [[NSFileManager defaultManager]
        createDirectoryAtPath:kDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSUInteger n = [self listBackups].count + 1;
    NSString *dest = [kDir stringByAppendingPathComponent:
        [NSString stringWithFormat:@"高德地图_%05lu.json", (unsigned long)n]];
    return [d writeToFile:dest options:NSDataWritingAtomic error:error];
}

- (BOOL)restoreFromPath:(NSString *)path error:(NSError **)error {
    NSData *d = [NSData dataWithContentsOfFile:path options:0 error:error];
    if (!d) return NO;
    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:error];
    if (!j) return NO;
    return [self saveActive:j error:error];
}

@end
