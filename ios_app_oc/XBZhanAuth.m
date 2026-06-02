#import "XBZhanAuth.h"
#import <CommonCrypto/CommonDigest.h>
#import <UIKit/UIKit.h>

static NSString *const kAPIBase   = @"http://api2.xbzhan.com";
static NSString *const kSOFT      = @"N7vfi8ZKGlXO2SArgC";
static NSString *const kSOFT_KEY  = @"GC6tgXFhCreKn7s323CLtENVyP4CYsih";
static NSString *const kRC4_KEY   = @"BzDNbwMVTaVLqEWD4E2ISoA4dn9w0LCyLXfbup9Uj93asD6z";
static NSString *const kCACHE_KEY = @"xb_cached_card_key";

static NSData *rc4(NSData *data, NSString *keyStr) {
    const char *k = keyStr.UTF8String;
    NSUInteger kl = strlen(k);
    uint8_t S[256];
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + k[i % kl]) & 0xFF;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }
    NSMutableData *out = [NSMutableData dataWithLength:data.length];
    const uint8_t *in = data.bytes; uint8_t *o = out.mutableBytes;
    int ii = 0, jj = 0;
    for (NSUInteger n = 0; n < data.length; n++) {
        ii = (ii + 1) & 0xFF; jj = (jj + S[ii]) & 0xFF;
        uint8_t t = S[ii]; S[ii] = S[jj]; S[jj] = t;
        o[n] = in[n] ^ S[(S[ii] + S[jj]) & 0xFF];
    }
    return out;
}

static NSString *toHex(NSData *d) {
    const uint8_t *b = d.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:d.length * 2];
    for (NSUInteger i = 0; i < d.length; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

static NSData *fromHex(NSString *hex) {
    NSMutableData *d = [NSMutableData dataWithCapacity:hex.length / 2];
    for (NSUInteger i = 0; i + 1 < hex.length; i += 2) {
        unsigned int v; [[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i,2)]] scanHexInt:&v];
        uint8_t b = v; [d appendBytes:&b length:1];
    }
    return d;
}

static NSString *md5(NSString *s) {
    const char *c = s.UTF8String;
    uint8_t dg[CC_MD5_DIGEST_LENGTH];
    CC_MD5(c, (CC_LONG)strlen(c), dg);
    return toHex([NSData dataWithBytes:dg length:CC_MD5_DIGEST_LENGTH]);
}

@interface XBZhanAuth ()
@property (nonatomic, copy) NSString *cardKey;
@property (nonatomic, copy) NSString *sessionCookie;
@property (nonatomic, assign) BOOL initialized;
@property (nonatomic, strong) NSTimer *hbTimer;
@end

@implementation XBZhanAuth

+ (instancetype)shared {
    static XBZhanAuth *s; static dispatch_once_t t;
    dispatch_once(&t, ^{ s = [self new]; });
    return s;
}

- (NSString *)loadCachedKey {
    return [[NSUserDefaults standardUserDefaults] stringForKey:kCACHE_KEY] ?: @"";
}

- (NSDictionary *)buildBase {
    NSString *host = NSProcessInfo.processInfo.hostName;
    NSString *idfv = UIDevice.currentDevice.identifierForVendor.UUIDString ?: [NSUUID UUID].UUIDString;
    NSString *mac  = [host stringByAppendingString:idfv];
    NSString *ver  = UIDevice.currentDevice.systemVersion;
    return @{
        @"uuid":      [[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""],
        @"token":     [[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""],
        @"clientid":  [[md5(mac) substringToIndex:18] uppercaseString],
        @"version":   @"1.0",
        @"mac":       [[md5(mac) substringToIndex:12] uppercaseString],
        @"feature":   [[md5([mac stringByAppendingString:ver]) substringToIndex:16] uppercaseString],
        @"clientos":  [@"iOS " stringByAppendingString:ver],
        @"md5":       @""
    };
}

- (void)post:(NSString *)path data:(NSDictionary *)data completion:(void(^)(NSDictionary *))cb {
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:data options:NSJSONWritingSortedKeys error:nil];
    NSString *compact = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    NSString *encHex  = toHex(rc4([compact dataUsingEncoding:NSUTF8StringEncoding], kRC4_KEY));
    NSString *sign    = md5([NSString stringWithFormat:@"123%@456%@789", encHex, kSOFT_KEY]);
    NSDictionary *body = @{@"soft": kSOFT, @"data": encHex, @"sign": sign};

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:
        [NSURL URLWithString:[kAPIBase stringByAppendingString:path]]
        cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:30];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
      completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (!d) { dispatch_async(dispatch_get_main_queue(), ^{ cb(@{@"code":@-1,@"msg":@"网络错误"}); }); return; }
        NSDictionary *outer = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        if (![outer[@"status"] isEqualToString:@"success"]) {
            dispatch_async(dispatch_get_main_queue(), ^{ cb(@{@"code":@-1,@"msg":@"请求异常"}); });
            return;
        }
        NSData *dec = rc4(fromHex(outer[@"data"] ?: @""), kRC4_KEY);
        NSDictionary *inner = [NSJSONSerialization JSONObjectWithData:dec options:0 error:nil] ?: @{};
        dispatch_async(dispatch_get_main_queue(), ^{ cb(inner); });
    }] resume];
}

- (void)loginWithKey:(NSString *)key completion:(XBZhanCallback)completion {
    NSMutableDictionary *base = [[self buildBase] mutableCopy];
    void (^doLogin)(void) = ^{
        base[@"account"] = key;
        [self post:@"/api/login" data:base completion:^(NSDictionary *r) {
            NSInteger code = [r[@"code"] integerValue];
            NSString *msg  = r[@"msg"] ?: @"未知错误";
            BOOL ok = code == 200 || [msg containsString:@"成功"];
            if (ok) {
                self.cardKey = key;
                self.sessionCookie = r[@"cookie"] ?: r[@"param"] ?: @"";
                [[NSUserDefaults standardUserDefaults] setObject:key forKey:kCACHE_KEY];
                [self startHeartbeat];
            }
            completion(ok, msg);
        }];
    };
    if (self.initialized) { doLogin(); return; }
    [self post:@"/api/init" data:base completion:^(NSDictionary *r) {
        NSInteger code = [r[@"code"] integerValue];
        NSString *msg  = r[@"msg"] ?: @"";
        self.initialized = code == 200 || [msg containsString:@"成功"];
        if (!self.initialized) { completion(NO, [@"初始化失败: " stringByAppendingString:msg]); return; }
        doLogin();
    }];
}

- (void)unbindAllWithKey:(NSString *)key completion:(XBZhanCallback)completion {
    NSMutableDictionary *base = [[self buildBase] mutableCopy];
    base[@"account"] = key;
    [self post:@"/api/un_bind_all" data:base completion:^(NSDictionary *r) {
        NSInteger code = [r[@"code"] integerValue];
        NSString *msg  = r[@"msg"] ?: @"未知错误";
        completion(code == 200 || [msg containsString:@"成功"], msg);
    }];
}

- (void)startHeartbeat {
    [_hbTimer invalidate];
    _hbTimer = [NSTimer scheduledTimerWithTimeInterval:120 repeats:YES block:^(NSTimer *t) {
        NSMutableDictionary *d = [[self buildBase] mutableCopy];
        d[@"account"] = self.cardKey ?: @"";
        d[@"cookie"]  = self.sessionCookie ?: @"";
        [self post:@"/api/heartbeat" data:d completion:^(NSDictionary *r) {}];
    }];
}

@end
