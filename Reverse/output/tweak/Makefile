TARGET  := iphone:clang:16.5:15.0
ARCHS   = arm64 arm64e
INSTALL_TARGET_PROCESSES = AMapiPhone

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = AmapNewDevice

AmapNewDevice_FILES        = Tweak.x bypass.mm spoof.mm profile.mm
AmapNewDevice_CFLAGS       = -fobjc-arc
AmapNewDevice_FRAMEWORKS   = UIKit Foundation Security CoreFoundation AdSupport
AmapNewDevice_LIBRARIES    = substrate

include $(THEOS)/makefiles/tweak.mk
