// AmapNewDevice — 高德地图一键新机 Tweak
// 目标: com.autonavi.amap / AMapiPhone
// 依赖: ElleKit (Dopamine)

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import "profile.h"
#import "bypass.h"
#import "spoof.h"
#import "clean.h"
#import "tlog.h"

// ── UIKit hooks（UIKit 必定已加载，无需 %group）────────────────
%hook UIDevice
- (NSUUID *)identifierForVendor {
    return [[NSUUID alloc] initWithUUIDString:gIDFV];
}
- (NSString *)name {
    return @"iPhone";
}
%end

// ── AdSupport hook — 延迟到 %ctor 内 dlopen 后再 %init ────────
%group GAdSupport
%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier {
    return [[NSUUID alloc] initWithUUIDString:gIDFA];
}
%end
%end

// ── CoreTelephony hook — 运营商指纹伪装 ──────────────────────────
%group GCoreTelephony
%hook CTCarrier
- (NSString *)carrierName        { return gCarrierName; }
- (NSString *)mobileCountryCode  { return gCarrierMCC; }
- (NSString *)mobileNetworkCode  { return gCarrierMNC; }
- (NSString *)isoCountryCode     { return gCarrierISO; }
%end
%end

// ── 云端同步写入拦截（一键新机后阻止云端数据落盘）────────────────
static NSSet *sSyncBlockedFiles(void) {
    static NSSet *s;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        s = [NSSet setWithObjects:
            @"favoriteIndex.plist", @"cachedSearchData.plist",
            @"cachedSearchHomeData.plist", @"search_home.plist",
            @"PoiDetailUserBehavior.plist", nil];
    });
    return s;
}

static BOOL shouldBlockWrite(NSString *path) {
    if (!gBlockSync || !path) return NO;
    NSString *prefsDir = [NSHomeDirectory()
        stringByAppendingPathComponent:@"Library/Preferences"];
    return [path hasPrefix:prefsDir]
        && [sSyncBlockedFiles() containsObject:path.lastPathComponent];
}

%hook NSDictionary
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)a {
    return shouldBlockWrite(path) ? YES : %orig;
}
%end

%hook NSArray
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)a {
    return shouldBlockWrite(path) ? YES : %orig;
}
%end

%hook NSData
- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)a {
    return shouldBlockWrite(path) ? YES : %orig;
}
%end

// ── 初始化 ────────────────────────────────────────────────────
// 顺序：loadProfile（读 JSON） → bypass（安装 C hook） → spoof（Keychain/Prefs）
// → dlopen AdSupport → %init(GAdSupport)
%ctor {
    @autoreleasepool {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        if ([bid isEqualToString:@"com.autonavi.amap"]) {
            [@"1" writeToFile:@"/tmp/amaptweak_loaded" atomically:YES encoding:NSUTF8StringEncoding error:nil];
            tlog(@"tweak_loaded", nil);
            loadProfile();
            if (gBlockSync) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 180 * NSEC_PER_SEC),
                    dispatch_get_main_queue(), ^{
                    gBlockSync = NO;
                    [[NSFileManager defaultManager] removeItemAtPath:
                        @"/var/mobile/Documents/amap_profiles/block_sync" error:nil];
                });
            }
            installBypassHooks();
            installSpoofHooks();
            initCleanHooks();
            %init;
            dlopen("/System/Library/Frameworks/AdSupport.framework/AdSupport", RTLD_NOW);
            %init(GAdSupport);
            dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_NOW);
            %init(GCoreTelephony);
        }
    }
}
