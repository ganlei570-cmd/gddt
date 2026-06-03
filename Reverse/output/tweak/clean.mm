#import <Foundation/Foundation.h>
#import "clean.h"

static NSArray<NSString *> *safariTargets(void) {
    NSString *base = @"/var/mobile/Library/Safari";
    NSArray *names = @[
        @"History.db", @"History.db-shm", @"History.db-wal",
        @"BrowserState.db", @"BrowserState.db-shm", @"BrowserState.db-wal",
        @"SafariTabs.db", @"SafariTabs.db-shm", @"SafariTabs.db-wal",
        @"CloudTabs.db", @"CloudTabs.db-shm", @"CloudTabs.db-wal",
    ];
    NSMutableArray *paths = [NSMutableArray array];
    for (NSString *n in names)
        [paths addObject:[base stringByAppendingPathComponent:n]];
    return paths;
}

static void handleClearSafari(CFNotificationCenterRef c, void *o,
                               CFStringRef n, const void *obj, CFDictionaryRef i) {
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in safariTargets())
        [fm removeItemAtPath:p error:nil];
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
