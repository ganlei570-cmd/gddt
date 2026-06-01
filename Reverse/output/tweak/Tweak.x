// AmapNewDevice — 高德地图一键新机 Tweak
// 目标: com.autonavi.amap / AMapiPhone
// 依赖: ElleKit (Dopamine)

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import "profile.h"
#import "bypass.h"
#import "spoof.h"

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
// ASIdentifierManager 可能懒加载，必须在 AdSupport 加载后再注册 hook
%group GAdSupport
%hook ASIdentifierManager
- (NSUUID *)advertisingIdentifier {
    return [[NSUUID alloc] initWithUUIDString:gIDFA];
}
%end
%end

// ── 初始化 ────────────────────────────────────────────────────
// 顺序：loadProfile（读 JSON） → bypass（安装 C hook） → spoof（Keychain/Prefs）
// → dlopen AdSupport → %init(GAdSupport)
%ctor {
    @autoreleasepool {
        loadProfile();
        installBypassHooks();
        installSpoofHooks();
        dlopen("/System/Library/Frameworks/AdSupport.framework/AdSupport", RTLD_NOW);
        %init(GAdSupport);
    }
}
