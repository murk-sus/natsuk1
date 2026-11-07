THEOS ?= /opt/theos
LDID ?= /usr/local/bin/ldid
TARGET := iphone:clang:latest:14.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME := XMLFuzz
XMLFuzz_FILES := main.m fuzz.m target.m iogpu.m logger.m
XMLFuzz_RESOURCE_FILES := Info.plist
XMLFuzz_FRAMEWORKS := UIKit Foundation IOKit IOSurface
XMLFuzz_CFLAGS := -fobjc-arc -O2 -Wall -Wno-unused-function
XMLFuzz_LDFLAGS := -fuse-ld=/usr/bin/ld64.lld -Wl,-platform_version,ios,14.0,14.0
XMLFuzz_CODESIGN_FLAGS := -Sentitlements.plist

include $(THEOS)/makefiles/application.mk

.PHONY: ipa
ipa: all
	mkdir -p .theos/ipa/Payload
	rm -rf .theos/ipa/Payload/XMLFuzz.app
	cp -a .theos/obj/debug/XMLFuzz.app .theos/ipa/Payload/
	$(LDID) -Sentitlements.plist .theos/ipa/Payload/XMLFuzz.app/XMLFuzz
	cd .theos/ipa && rm -f ../../XMLFuzz.ipa && zip -qry ../../XMLFuzz.ipa Payload
