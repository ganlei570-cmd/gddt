#import "ProfileManager.h"
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <sys/mount.h>
#import <signal.h>

static NSString *const kBackupDir  = @"/var/mobile/Documents/amap_backups";
static NSString *const kActivePtr  = @"/var/mobile/Documents/amap_backups/active_backup";

static NSArray<NSString *> *kcKeys(void) {
    return @[
        @"com.autonavi.amap/udid",   @"com.autonavi.amap/vimsi",
        @"com.autonavi.amap/vimei",  @"com.autonavi.amap/tid",
        @"com.autonavi.amap/public_key", @"gd_amap/gd_amap",
        @"com.amap.adiu.key/com.amap.adiu.key",
        @"0.umid_v1/com.autonavi.amap",
        @"PNS_UniqueId_com.autonavi.amap/PNS_UniqueId_com.autonavi.amap",
    ];
}

static NSArray<NSString *> *sysVerPool(NSString *real) {
    NSDictionary *m = @{
        @"15.4":@[@"15.4",@"15.4.1"],   @"15.4.1":@[@"15.4",@"15.4.1"],
        @"15.5":@[@"15.5"],
        @"15.6":@[@"15.6",@"15.6.1"],   @"15.6.1":@[@"15.6",@"15.6.1"],
        @"15.7":@[@"15.7",@"15.7.1"],   @"15.7.1":@[@"15.7",@"15.7.1",@"15.7.2"],
        @"16.0":@[@"16.0",@"16.0.1"],   @"16.0.1":@[@"16.0",@"16.0.1",@"16.0.2"],
        @"16.1":@[@"16.1",@"16.1.1"],   @"16.1.1":@[@"16.1",@"16.1.1"],
        @"16.2":@[@"16.2"],
        @"16.3":@[@"16.3",@"16.3.1"],   @"16.3.1":@[@"16.3",@"16.3.1"],
        @"16.4":@[@"16.4",@"16.4.1"],   @"16.4.1":@[@"16.4",@"16.4.1"],
        @"16.5":@[@"16.5",@"16.5.1"],   @"16.5.1":@[@"16.5",@"16.5.1"],
        @"16.6":@[@"16.6",@"16.6.1"],   @"16.6.1":@[@"16.6",@"16.6.1"],
    };
    return m[real] ?: @[real];
}

@implementation ProfileManager

- (NSString *)amapProfileDir {
    NSString *container = [self findAmapContainer];
    NSString *docs = container
        ? [container stringByAppendingPathComponent:@"Documents"]
        : @"/var/mobile/Documents";
    return [docs stringByAppendingPathComponent:@"amap_profiles"];
}

- (NSString *)activePath {
    return [[self amapProfileDir] stringByAppendingPathComponent:@"active.json"];
}

+ (instancetype)shared {
    static ProfileManager *s; static dispatch_once_t t;
    dispatch_once(&t, ^{ s = [self new]; [s reload]; });
    return s;
}

- (void)reload {
    NSData *d = [NSData dataWithContentsOfFile:[self activePath]];
    NSDictionary *j = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
    self.activeIdfv = j[@"idfv"] ?: @"";
    self.activeBackupName = [[NSString alloc] initWithContentsOfFile:kActivePtr
        encoding:NSUTF8StringEncoding error:nil] ?: @"";
}

- (NSDictionary *)generateProfile {
    NSMutableDictionary *kc = [NSMutableDictionary dictionary];
    for (NSString *k in kcKeys()) kc[k] = @"CLEAR";
    NSMutableDictionary *ud = [NSMutableDictionary dictionary];
    char machine[64] = {0};
    size_t sz = sizeof(machine);
    sysctlbyname("hw.machine", machine, &sz, NULL, 0);
    NSString *machineStr = machine[0] ? @(machine) : @"iPhone13,2";
    NSArray *deviceNames = @[@"iPhone", @"的iPhone", @"我的iPhone", @"手机", @"iPhone手机"];
    NSString *deviceName = deviceNames[arc4random_uniform((uint32_t)deviceNames.count)];
    NSString *osVer = [UIDevice currentDevice].systemVersion;
    NSArray *verPool = sysVerPool(osVer);
    NSString *sysVer = verPool[arc4random_uniform((uint32_t)verPool.count)];
    struct statfs st;
    long long realTotal = 126282547200LL;
    if (statfs("/var/mobile", &st) == 0 && st.f_bsize > 0)
        realTotal = (long long)st.f_blocks * (long long)st.f_bsize;
    double scale = 1.0 + ((double)((int)arc4random_uniform(11) - 5)) / 100.0;
    long long dTotal = (long long)(realTotal * scale);
    long long dFree  = dTotal / 100 * (20 + arc4random_uniform(41));
    uint8_t mb[6]; arc4random_buf(mb, sizeof(mb)); mb[0] = (mb[0] & 0xFE) | 0x02;
    NSString *wifiMac = [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x",mb[0],mb[1],mb[2],mb[3],mb[4],mb[5]];
    NSArray *carriers = @[
        @{@"carrier_name":@"中国移动",@"carrier_mcc":@"460",@"carrier_mnc":@"00",@"carrier_iso":@"cn"},
        @{@"carrier_name":@"中国移动",@"carrier_mcc":@"460",@"carrier_mnc":@"02",@"carrier_iso":@"cn"},
        @{@"carrier_name":@"中国联通",@"carrier_mcc":@"460",@"carrier_mnc":@"01",@"carrier_iso":@"cn"},
        @{@"carrier_name":@"中国联通",@"carrier_mcc":@"460",@"carrier_mnc":@"06",@"carrier_iso":@"cn"},
        @{@"carrier_name":@"中国电信",@"carrier_mcc":@"460",@"carrier_mnc":@"03",@"carrier_iso":@"cn"},
        @{@"carrier_name":@"中国电信",@"carrier_mcc":@"460",@"carrier_mnc":@"05",@"carrier_iso":@"cn"},
    ];
    NSDictionary *carrier = carriers[arc4random_uniform((uint32_t)carriers.count)];
    NSMutableDictionary *profile = [@{
        @"idfv":               [NSUUID UUID].UUIDString.uppercaseString,
        @"idfa":               @"00000000-0000-0000-0000-000000000000",
        @"machine":            machineStr,
        @"device_name":        deviceName,
        @"boot_session_uuid":  [NSUUID UUID].UUIDString.uppercaseString,
        @"hardware_uuid":      [NSUUID UUID].UUIDString.uppercaseString,
        @"keychain": kc, @"userdefaults": ud,
    } mutableCopy];
    [profile addEntriesFromDictionary:carrier];
    profile[@"sys_ver"]    = sysVer;
    profile[@"disk_total"] = @(dTotal);
    profile[@"disk_free"]  = @(dFree);
    profile[@"wifi_mac"]   = wifiMac;
    profile[@"utdid_gd_amap"]  = [NSUUID UUID].UUIDString.uppercaseString;
    uint8_t adiuRaw[32]; arc4random_buf(adiuRaw, sizeof(adiuRaw));
    profile[@"utdid_adiu_key"] = [[NSData dataWithBytes:adiuRaw length:32] base64EncodedStringWithOptions:0];
    return [profile copy];
}

- (BOOL)saveActive:(NSDictionary *)profile error:(NSError **)error {
    [[NSFileManager defaultManager] createDirectoryAtPath:[self amapProfileDir]
        withIntermediateDirectories:YES attributes:nil error:nil];
    NSData *data = [NSJSONSerialization dataWithJSONObject:profile
        options:NSJSONWritingPrettyPrinted error:error];
    if (!data) return NO;
    BOOL ok = [data writeToFile:[self activePath] options:NSDataWritingAtomic error:error];
    if (ok) self.activeIdfv = profile[@"idfv"] ?: @"";
    return ok;
}

- (NSString *)findAmapContainer {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *base = @"/var/mobile/Containers/Data/Application";
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:base error:nil]) {
        NSString *plist = [NSString stringWithFormat:
            @"%@/%@/.com.apple.mobile_container_manager.metadata.plist", base, uuid];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:plist];
        if ([meta[@"MCMMetadataIdentifier"] isEqualToString:@"com.autonavi.amap"])
            return [base stringByAppendingPathComponent:uuid];
    }
    return nil;
}

- (unsigned long long)dirSize:(NSString *)path {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSDirectoryEnumerator *e = [fm enumeratorAtPath:path];
    unsigned long long total = 0;
    NSString *f;
    while ((f = [e nextObject])) {
        NSDictionary *attr = [fm attributesOfItemAtPath:
            [path stringByAppendingPathComponent:f] error:nil];
        if ([attr[NSFileType] isEqualToString:NSFileTypeRegular])
            total += [attr[NSFileSize] unsignedLongLongValue];
    }
    return total;
}

- (void)copyDir:(NSString *)src to:(NSString *)dst {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:dst withIntermediateDirectories:YES attributes:nil error:nil];
    for (NSString *item in [fm contentsOfDirectoryAtPath:src error:nil]) {
        NSString *s = [src stringByAppendingPathComponent:item];
        NSString *d = [dst stringByAppendingPathComponent:item];
        BOOL isDir = NO;
        [fm fileExistsAtPath:s isDirectory:&isDir];
        if (isDir) [self copyDir:s to:d];
        else [fm copyItemAtPath:s toPath:d error:nil];
    }
}

- (NSString *)createBackupWithProfile:(NSDictionary *)profile container:(NSString *)container {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:kBackupDir withIntermediateDirectories:YES attributes:nil error:nil];

    NSInteger maxNum = 0;
    for (NSString *f in [fm contentsOfDirectoryAtPath:kBackupDir error:nil]) {
        if (![f hasPrefix:@"高德地图_"]) continue;
        NSInteger n = [[f substringFromIndex:5] integerValue];
        if (n > maxNum) maxNum = n;
    }
    NSString *name = [NSString stringWithFormat:@"高德地图_%05ld", (long)(maxNum + 1)];
    NSString *dir = [kBackupDir stringByAppendingPathComponent:name];
    [fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];

    NSData *pd = [NSJSONSerialization dataWithJSONObject:profile options:NSJSONWritingPrettyPrinted error:nil];
    [pd writeToFile:[dir stringByAppendingPathComponent:@"profile.json"] atomically:YES];

    unsigned long long sizeMB = [self dirSize:dir] / (1024 * 1024);
    UIDevice *dev = [UIDevice currentDevice];
    NSDateFormatter *fmt = [NSDateFormatter new];
    fmt.dateFormat = @"yyyy-MM-dd HH:mm";
    NSDictionary *meta = @{
        @"model": dev.model ?: @"iPhone",
        @"name":  dev.name  ?: @"iPhone",
        @"ios":   dev.systemVersion ?: @"",
        @"date":  [fmt stringFromDate:[NSDate date]],
        @"size_mb": @(sizeMB),
        @"idfv":  profile[@"idfv"] ?: @"",
    };
    [[NSJSONSerialization dataWithJSONObject:meta options:0 error:nil]
        writeToFile:[dir stringByAppendingPathComponent:@"meta.json"] atomically:YES];
    return name;
}

- (NSArray<NSString *> *)findAmapAppGroups {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *base = @"/var/mobile/Containers/Shared/AppGroup";
    NSMutableArray *result = [NSMutableArray array];
    for (NSString *uuid in [fm contentsOfDirectoryAtPath:base error:nil]) {
        NSString *plist = [NSString stringWithFormat:
            @"%@/%@/.com.apple.mobile_container_manager.metadata.plist", base, uuid];
        NSDictionary *meta = [NSDictionary dictionaryWithContentsOfFile:plist];
        NSString *ident = meta[@"MCMMetadataIdentifier"] ?: @"";
        if ([ident containsString:@"amap"] || [ident containsString:@"autonavi"])
            [result addObject:[base stringByAppendingPathComponent:uuid]];
    }
    return result;
}

- (void)killAmapProcess {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    sysctl(mib, 4, NULL, &size, NULL, 0);
    struct kinfo_proc *procs = malloc(size);
    if (!procs) return;
    sysctl(mib, 4, procs, &size, NULL, 0);
    int count = (int)(size / sizeof(struct kinfo_proc));
    for (int i = 0; i < count; i++) {
        NSString *name = [NSString stringWithUTF8String:procs[i].kp_proc.p_comm];
        if ([name hasPrefix:@"AMapiPhone"])
            kill(procs[i].kp_proc.p_pid, SIGKILL);
    }
    free(procs);
}

- (void)clearDir:(NSString *)path fm:(NSFileManager *)fm {
    for (NSString *item in [fm contentsOfDirectoryAtPath:path error:nil])
        [fm removeItemAtPath:[path stringByAppendingPathComponent:item] error:nil];
}

- (void)clearAmapDataInContainer:(NSString *)container {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *docsPath = [container stringByAppendingPathComponent:@"Documents"];
    for (NSString *item in [fm contentsOfDirectoryAtPath:docsPath error:nil]) {
        if ([item isEqualToString:@"amap_profiles"]) continue;
        [fm removeItemAtPath:[docsPath stringByAppendingPathComponent:item] error:nil];
    }
    [self clearDir:[container stringByAppendingPathComponent:@"tmp"] fm:fm];
    NSString *lib = [container stringByAppendingPathComponent:@"Library"];
    for (NSString *sub in @[@"Caches", @"Application Support", @"WebKit", @"SplashBoard", @"Cookies", @"Preferences"]) {
        [self clearDir:[lib stringByAppendingPathComponent:sub] fm:fm];
    }
    NSString *prefsBase = @"/var/mobile/Library/Preferences";
    for (NSString *f in [fm contentsOfDirectoryAtPath:prefsBase error:nil]) {
        if (![f hasPrefix:@"com.autonavi.amap"] && ![f hasPrefix:@"com.amap"]) continue;
        [fm removeItemAtPath:[prefsBase stringByAppendingPathComponent:f] error:nil];
    }
    for (NSString *group in [self findAmapAppGroups])
        [self clearDir:group fm:fm];
}

- (void)newMachineAsync:(void(^)(BOOL done, NSString *status, NSError *err))cb {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        void(^prog)(NSString *) = ^(NSString *s) {
            dispatch_async(dispatch_get_main_queue(), ^{ cb(NO, s, nil); });
        };

        NSDictionary *profile = [self generateProfile];
        NSString *container   = [self findAmapContainer];
        NSString *backupName  = nil;

        if (container) {
            prog(@"正在关闭高德...");
            [self killAmapProcess];
            sleep(1);
            prog(@"正在备份高德数据...");
            backupName = [self createBackupWithProfile:profile container:container];
            prog(@"正在清理高德数据...");
            [self clearAmapDataInContainer:container];
            NSString *kcAllowedPath = [[self amapProfileDir] stringByAppendingPathComponent:@"kc_allowed.json"];
            NSData *kcData = [NSData dataWithContentsOfFile:kcAllowedPath];
            if (kcData) {
                NSMutableArray *arr = [[NSJSONSerialization JSONObjectWithData:kcData options:0 error:nil] mutableCopy];
                if ([arr isKindOfClass:[NSArray class]]) {
                    NSMutableArray *toRemove = [NSMutableArray arrayWithArray:kcKeys()];
                    [toRemove addObject:@"Soft/SGTMAGIC"];
                    [toRemove addObject:@"D7CA1CE6DE13787FD151D81C8E2C8C56/D7CA1CE6DE13787FD151D81C8E2C8C56"];
                    for (NSString *k in toRemove) [arr removeObject:k];
                    NSData *out = [NSJSONSerialization dataWithJSONObject:arr options:0 error:nil];
                    if (out) [out writeToFile:kcAllowedPath atomically:YES];
                }
            }
        } else {
            prog(@"未找到高德数据，直接生成新指纹...");
        }

        prog(@"正在写入新指纹...");
        NSError *err = nil;
        [self saveActive:profile error:&err];
        // 标记需要重置 UTDID，Tweak 启动时删旧 Keychain 条目
        [[NSFileManager defaultManager]
            createFileAtPath:[[self amapProfileDir] stringByAppendingPathComponent:@"utdid_reset.flag"]
                    contents:[NSData data] attributes:nil];

        if (!err && backupName) {
            self.activeBackupName = backupName;
            [backupName writeToFile:kActivePtr atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        dispatch_async(dispatch_get_main_queue(), ^{ cb(YES, @"完成", err); });
    });
}

- (BOOL)clearKeychainWithError:(NSError **)error {
    NSData *d = [NSData dataWithContentsOfFile:[self activePath]];
    NSMutableDictionary *p = d
        ? [[NSJSONSerialization JSONObjectWithData:d options:NSJSONReadingMutableContainers error:nil] mutableCopy]
        : [[self generateProfile] mutableCopy];
    if (!p) p = [[self generateProfile] mutableCopy];
    NSMutableDictionary *kc = [NSMutableDictionary dictionary];
    for (NSString *k in kcKeys()) kc[k] = @"CLEAR";
    p[@"keychain"] = kc;
    return [self saveActive:p error:error];
}

- (NSArray<NSDictionary *> *)listBackups {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *result = [NSMutableArray array];
    for (NSString *name in [fm contentsOfDirectoryAtPath:kBackupDir error:nil]) {
        if (![name hasPrefix:@"高德地图_"]) continue;
        NSString *dir = [kBackupDir stringByAppendingPathComponent:name];
        BOOL isDir = NO;
        [fm fileExistsAtPath:dir isDirectory:&isDir];
        if (!isDir) continue;
        NSData *md = [NSData dataWithContentsOfFile:[dir stringByAppendingPathComponent:@"meta.json"]];
        NSDictionary *meta = md ? [NSJSONSerialization JSONObjectWithData:md options:0 error:nil] : @{};
        [result addObject:@{
            @"name":    name,
            @"path":    dir,
            @"idfv":    meta[@"idfv"]    ?: @"",
            @"model":   meta[@"model"]   ?: @"iPhone",
            @"date":    meta[@"date"]    ?: @"",
            @"size_mb": meta[@"size_mb"] ?: @0,
            @"active":  @([name isEqualToString:self.activeBackupName]),
        }];
    }
    return [result sortedArrayUsingComparator:^(NSDictionary *a, NSDictionary *b) {
        BOOL aAct = [a[@"active"] boolValue], bAct = [b[@"active"] boolValue];
        if (aAct != bAct) return aAct ? NSOrderedAscending : NSOrderedDescending;
        return [a[@"name"] compare:b[@"name"]];
    }];
}

- (BOOL)deleteBackupAtPath:(NSString *)path error:(NSError **)error {
    return [[NSFileManager defaultManager] removeItemAtPath:path error:error];
}

- (BOOL)restoreFromPath:(NSString *)path error:(NSError **)error {
    NSString *profilePath = [path stringByAppendingPathComponent:@"profile.json"];
    NSData *d = [NSData dataWithContentsOfFile:profilePath options:0 error:error];
    if (!d) return NO;
    NSDictionary *j = [NSJSONSerialization JSONObjectWithData:d options:0 error:error];
    if (!j) return NO;
    return [self saveActive:j error:error];
}

@end
