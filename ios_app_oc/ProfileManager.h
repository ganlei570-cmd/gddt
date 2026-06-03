#import <Foundation/Foundation.h>

@interface ProfileManager : NSObject
+ (instancetype)shared;
@property (nonatomic, copy) NSString *activeIdfv;
@property (nonatomic, copy) NSString *activeBackupName;
- (void)reload;
- (void)newMachineAsync:(void(^)(BOOL done, NSString *status, NSError *err))callback;
- (BOOL)clearKeychainWithError:(NSError **)error;
- (NSArray<NSDictionary *> *)listBackups;
- (BOOL)deleteBackupAtPath:(NSString *)path error:(NSError **)error;
- (BOOL)restoreFromPath:(NSString *)path error:(NSError **)error;
@end
