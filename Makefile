# Compiler target — no SDK version pinned; uses whatever landed in $THEOS/sdks
ARCHS  = arm64 arm64e
TARGET = iphone:clang::14.0

THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SwipePatcher

SwipePatcher_FILES   = Tweak.x
SwipePatcher_CFLAGS  = -fobjc-arc \
                        -O2 \
                        -Wall \
                        -Wno-unused-function \
                        -fvisibility=hidden
SwipePatcher_LDFLAGS = -Wl,-dead_strip
SwipePatcher_FRAMEWORKS         = UIKit Foundation
SwipePatcher_PRIVATE_FRAMEWORKS =
SwipePatcher_LIBRARIES          = substrate

include $(THEOS)/makefiles/tweak.mk
