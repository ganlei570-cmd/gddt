#import <Foundation/Foundation.h>

typedef void(^XBZhanCallback)(BOOL ok, NSString *msg);

@interface XBZhanAuth : NSObject
+ (instancetype)shared;
@property (nonatomic, readonly, copy) NSString *cardKey;
- (NSString *)loadCachedKey;
- (void)loginWithKey:(NSString *)key completion:(XBZhanCallback)completion;
- (void)unbindAllWithKey:(NSString *)key completion:(XBZhanCallback)completion;
@end
