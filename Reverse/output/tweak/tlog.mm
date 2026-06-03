#import "tlog.h"
#import <UIKit/UIKit.h>

#define TLOG_URL      @"http://49.234.20.227:8888/log"
#define TLOG_LOGFILE  @"/tmp/amaptweak_diag.log"

// 同步写本地文件，保证崩溃前已落盘
static void tlog_local(NSString *event, NSDictionary *info) {
    NSTimeInterval ts = [[NSDate date] timeIntervalSince1970];
    NSMutableString *line = [NSMutableString stringWithFormat:@"[%.3f] %@", ts, event];
    if (info.count) {
        for (NSString *k in info)
            [line appendFormat:@" %@=%@", k, info[k]];
    }
    [line appendString:@"\n"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:TLOG_LOGFILE];
    if (!fh) {
        [@"" writeToFile:TLOG_LOGFILE atomically:NO encoding:NSUTF8StringEncoding error:nil];
        fh = [NSFileHandle fileHandleForWritingAtPath:TLOG_LOGFILE];
    }
    if (fh) {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh synchronizeFile];
        [fh closeFile];
    }
}

extern "C" void tlog(NSString *event, NSDictionary *info) {
    tlog_local(event, info);

    NSMutableDictionary *body = [NSMutableDictionary dictionary];
    body[@"event"] = event ?: @"unknown";
    body[@"src"]   = @"tweak";
    body[@"idfv"]  = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"";
    body[@"ios"]   = [[UIDevice currentDevice] systemVersion] ?: @"";
    if (info) [body addEntriesFromDictionary:info];

    NSData *data = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    if (!data) return;

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:TLOG_URL]
                                                       cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                   timeoutInterval:8];
    req.HTTPMethod = @"POST";
    req.HTTPBody = data;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        [[NSURLSession.sharedSession dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {}] resume];
    });
}
