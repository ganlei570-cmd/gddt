#import <Foundation/Foundation.h>

@interface Logger : NSObject
+ (void)log:(NSString *)event info:(NSDictionary *)info;
+ (void)log:(NSString *)event;
@end
