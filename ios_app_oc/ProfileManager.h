#import <Foundation/Foundation.h>

@interface ProfileManager : NSObject
+ (instancetype)shared;
@property (nonatomic, copy) NSString *activeIdfv;
- (void)reload;
- (BOOL)newMachineWithError:(NSError **)error;
- (BOOL)clearKeychainWithError:(NSError **)error;
- (NSArray<NSDictionary *> *)listBackups;
- (BOOL)backupWithError:(NSError **)error;
- (BOOL)restoreFromPath:(NSString *)path error:(NSError **)error;
@end
