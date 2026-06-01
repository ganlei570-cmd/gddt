#import <Foundation/Foundation.h>
#import "clean.h"

static NSString *const kSafariCookies =
    @"/var/mobile/Library/Cookies/com.apple.SafariShared.WebKit.Cookies.binarycookies";

static void handleClearSafari(CFNotificationCenterRef c, void *o,
                               CFStringRef n, const void *obj, CFDictionaryRef i) {
    [[NSFileManager defaultManager] removeItemAtPath:kSafariCookies error:nil];
}

void initCleanHooks(void) {
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        NULL,
        handleClearSafari,
        CFSTR("com.amap.newmachine.clearSafari"),
        NULL,
        CFNotificationSuspensionBehaviorDeliverImmediately);
}
