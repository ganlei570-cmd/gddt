#import "Logger.h"
#import <UIKit/UIKit.h>

#define LOG_URL @"http://49.234.20.227:8888/log"

@implementation Logger

+ (void)log:(NSString *)event info:(NSDictionary *)info {
    NSMutableDictionary *body = [NSMutableDictionary dictionary];
    body[@"event"] = event ?: @"unknown";
    body[@"idfv"] = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"";
    body[@"ios"] = [[UIDevice currentDevice] systemVersion] ?: @"";
    body[@"model"] = [[UIDevice currentDevice] model] ?: @"";
    body[@"app_ver"] = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"] ?: @"";
    if (info) [body addEntriesFromDictionary:info];

    NSData *data = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    if (!data) return;

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:LOG_URL]
                                                       cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                   timeoutInterval:8];
    req.HTTPMethod = @"POST";
    req.HTTPBody = data;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    NSURLSession *session = [NSURLSession sharedSession];
    [[session dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {}] resume];
}

+ (void)log:(NSString *)event {
    [self log:event info:nil];
}

@end
