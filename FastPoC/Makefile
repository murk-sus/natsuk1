THEOS ?= /opt/theos
LDID ?= /usr/local/bin/ldid
TARGET := iphone:clang:latest:14.0
ARCHS := arm64

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME := AGXReconnect
AGXReconnect_FILES := main.m poc.m logger.m
AGXReconnect_RESOURCE_FILES := Info.plist
AGXReconnect_FRAMEWORKS := UIKit Foundation IOKit IOSurface
AGXReconnect_CFLAGS := -fobjc-arc -O2 -Wall -Wno-unused-function
AGXReconnect_LDFLAGS := -fuse-ld=/usr/bin/ld64.lld -Wl,-platform_version,ios,14.0,14.0
AGXReconnect_CODESIGN_FLAGS := -Sentitlements.plist

include $(THEOS)/makefiles/application.mk

.PHONY: ipa
ipa: all
	mkdir -p .theos/ipa/Payload
	rm -rf .theos/ipa/Payload/AGXReconnect.app
	cp -a .theos/obj/debug/AGXReconnect.app .theos/ipa/Payload/
	$(LDID) -Sentitlements.plist .theos/ipa/Payload/AGXReconnect.app/AGXReconnect
	cd .theos/ipa && rm -f ../../AGXReconnect.ipa && zip -qry ../../AGXReconnect.ipa Payload
