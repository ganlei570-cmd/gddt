#import "ProfileManager.h"
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <signal.h>

static NSString *const kActive     = @"/var/mobile/Documents/amap_profiles/active.json";
static NSString *const kProfileDir = @"/var/mobile/Documents/amap_profiles";
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

@implementation ProfileManager

+ (instancetype)shared {
    static ProfileManager *s; static dispatch_once_t t;
    dispatch_once(&t, ^{ s = [self new]; [s reload]; });
    return s;
}

- (void)reload {
    NSData *d = [NSData dataWithContentsOfFile:kActive];
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
        @"idfv":    [NSUUID UUID].UUIDString.uppercaseString,
        @"idfa":    @"00000000-0000-0000-0000-000000000000",
        @"machine": machineStr,
        @"keychain": kc, @"userdefaults": ud,
    } mutableCopy];
    [profile addEntriesFromDictionary:carrier];
    return [profile copy];
}

- (BOOL)saveActive:(NSDictionary *)profile error:(NSError **)error {
    [[NSFileManager defaultManager] createDirectoryAtPath:kProfileDir
        withIntermediateDirectories:YES attributes:nil error:nil];
    NSData *data = [NSJSONSerialization dataWithJSONObject:profile
        options:NSJSONWritingPrettyPrinted error:error];
    if (!data) return NO;
    BOOL ok = [data writeToFile:kActive options:NSDataWritingAtomic error:error];
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
    [self clearDir:[container stringByAppendingPathComponent:@"Documents"] fm:fm];
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
            // 删除 allowed keychain 记录，让 tweak 下次启动对所有 amap key 全量拦截
            [[NSFileManager defaultManager] removeItemAtPath:
                @"/var/mobile/Documents/amap_profiles/kc_allowed.json" error:nil];
            // 写 block_sync 标记，让 tweak 拦截云端同步数据落盘
            [@"1" writeToFile:@"/var/mobile/Documents/amap_profiles/block_sync"
                atomically:YES encoding:NSUTF8StringEncoding error:nil];
        } else {
            prog(@"未找到高德数据，直接生成新指纹...");
        }

        prog(@"正在写入新指纹...");
        NSError *err = nil;
        [self saveActive:profile error:&err];

        if (!err && backupName) {
            self.activeBackupName = backupName;
            [backupName writeToFile:kActivePtr atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
        dispatch_async(dispatch_get_main_queue(), ^{ cb(YES, @"完成", err); });
    });
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
    if (![self saveActive:j error:error]) return NO;
    // 还原旧指纹后解除云端同步拦截，登录时云端会根据旧指纹自动推回数据
    [[NSFileManager defaultManager] removeItemAtPath:
        @"/var/mobile/Documents/amap_profiles/block_sync" error:nil];
    return YES;
}

@end
