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
- (NSUUID *)identifierForVendor { return [[NSUUID alloc] initWithUUIDString:gIDFV]; }
- (NSString *)name              { return gDeviceName ?: @"iPhone"; }
- (NSString *)systemVersion     { return gSysVer ?: %orig; }
%end

%hook NSFileManager
- (NSDictionary *)attributesOfFileSystemForPath:(NSString *)path error:(NSError **)error {
    NSDictionary *orig = %orig;
    if (!gDiskTotal || !gDiskFree || !orig) return orig;
    NSMutableDictionary *d = [orig mutableCopy];
    d[NSFileSystemSize]     = gDiskTotal;
    d[NSFileSystemFreeSize] = gDiskFree;
    return [d copy];
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

// ── 登录保护 —— 拦截 DTHbalSe 强制踢登录 ──────────────────────
%hook GDAccountCoreService
- (void)forceLogoutWithReason:(id)reason completeBlock:(id)block {
    tlog(@"logout_blocked", @{@"m": @"forceLogout"});
}
- (void)logout:(id)arg {
    tlog(@"logout_blocked", @{@"m": @"logout"});
}
%end

%hook ALBBLoginCenter
- (void)logout { }
- (void)logout:(id)arg { }
- (void)logoutAllAccounts { }
- (void)logoutWithCallBack:(id)cb { }
- (void)logoutWithClearSessionOnlyCookie:(id)arg { }
%end

%hook ALBBLogoutService
+ (void)logout { }
+ (void)logout:(id)arg { }
+ (void)logoutAllAccounts { }
+ (void)logoutWithCallBack:(id)cb { }
%end

%hook ALBBSession
- (void)logout { }
- (void)logout:(id)arg { }
- (void)clearSession { }
%end

%hook GDAccountAmapModel
- (void)forceLogoutWithReason:(id)reason completeBlock:(id)block { }
- (void)logout:(id)arg { }
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
