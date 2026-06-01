#pragma once
#import <Foundation/Foundation.h>

extern NSString *gIDFV;
extern NSString *gIDFA;
extern NSSet<NSString *> *gKeychainClearSet;
extern NSSet<NSString *> *gPrefClearSet;

#ifdef __cplusplus
extern "C" {
#endif
void loadProfile(void);
#ifdef __cplusplus
}
#endif
