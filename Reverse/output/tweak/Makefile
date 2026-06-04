TARGET  := iphone:clang:16.5:15.0
ARCHS   = arm64 arm64e
THEOS_PACKAGE_SCHEME = rootless
INSTALL_TARGET_PROCESSES = AMapiPhone

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AmapNewDevice

AmapNewDevice_FILES        = Tweak.x bypass.mm spoof.mm profile.mm clean.mm tlog.mm
AmapNewDevice_CFLAGS       = -fobjc-arc
AmapNewDevice_FRAMEWORKS   = UIKit Foundation Security CoreFoundation AdSupport CoreTelephony SystemConfiguration IOKit
AmapNewDevice_LIBRARIES    = substrate

include $(THEOS)/makefiles/tweak.mk
# build trigger
