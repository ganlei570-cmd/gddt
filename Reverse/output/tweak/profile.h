#pragma once
#import <Foundation/Foundation.h>

extern NSString *gIDFV;
extern NSString *gIDFA;
extern NSString *gMachine;
extern NSString *gDeviceName;
extern NSString *gCarrierName;
extern NSString *gCarrierMCC;
extern NSString *gCarrierMNC;
extern NSString *gCarrierISO;
extern NSString *gSysVer;
extern NSNumber *gDiskTotal;
extern NSNumber *gDiskFree;
extern NSString *gWifiMAC;
extern NSString *gBootSessionUUID;
extern NSString *gHardwareUUID;
extern NSMutableSet<NSString *> *gKeychainClearSet;
extern NSMutableSet<NSString *> *gKeychainAllowedSet;

#ifdef __cplusplus
extern "C" {
#endif
void loadProfile(void);
void saveKeychainAllowed(void);
#ifdef __cplusplus
}
#endif
