TARGET  := iphone:clang:16.5:14.0
ARCHS   = arm64 arm64e
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = YiJianXinJi

YiJianXinJi_FILES      = main.m AppDelegate.m LoginViewController.m MainViewController.m BackupViewController.m XBZhanAuth.m ProfileManager.m Logger.m
YiJianXinJi_FRAMEWORKS = UIKit Foundation Security
YiJianXinJi_CFLAGS     = -fobjc-arc -Wno-deprecated-declarations
YiJianXinJi_CODESIGN_FLAGS = -Sentitlements.plist
YiJianXinJi_LDFLAGS    = -dead_strip_dylibs
YiJianXinJi_RESOURCE_FILES = Info.plist

include $(THEOS)/makefiles/application.mk
