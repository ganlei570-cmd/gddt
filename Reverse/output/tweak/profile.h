#pragma once
#import <Foundation/Foundation.h>

extern NSString *gIDFV;
extern NSString *gIDFA;
extern NSSet<NSString *> *gKeychainClearSet;
extern NSSet<NSString *> *gPrefClearSet;

void loadProfile(void);
