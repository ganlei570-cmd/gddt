#pragma once
#import <Foundation/Foundation.h>

extern NSString *gIDFV;
extern NSString *gIDFA;
extern NSString *gMachine;
extern NSString *gCarrierName;
extern NSString *gCarrierMCC;
extern NSString *gCarrierMNC;
extern NSString *gCarrierISO;
extern NSMutableSet<NSString *> *gKeychainClearSet;
extern NSSet<NSString *> *gPrefClearSet;

#ifdef __cplusplus
extern "C" {
#endif
void loadProfile(void);
#ifdef __cplusplus
}
#endif
