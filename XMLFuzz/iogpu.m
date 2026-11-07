#import "iogpu.h"
#import "fuzz.h"
#import "logger.h"
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <fcntl.h>

// IOGPUDeviceUserClient selector table (27.2).  si = scalarInputCount,
// szi = structureInputSize (0xffffffff = variable).
static const uint32_t kSi[56] = {
    0,0,0,0,0,0,0,1,0,1, 2,2,2,1,2,1,0,0,1,1,
    1,0,0,0,2,4,1,1,0,1, 2,2,2,1,2,3,1,0,0,1,
    1,2,1,2,1,1,2,2,2,1, 1,3,2,2,2,0
};
static const uint32_t kSzi[56] = {
    0,0,0,0,0,0,0xffffffff,0,0xffffffff,0, 0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0xffffffff,12,4,0,0, 0,0,0,0,0,0,0,24,24,0,
    0,0,0,0,0xffffffff,0,0,0,0,0, 0,0,0xffffffff,0xffffffff,0,0
};

static uint64_t g_rng = 0x123456789abcdefULL;
static uint64_t rnd64(void) { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17; return g_rng; }

static NSString *dump_dir(void)
{
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                        NSUserDomainMask, YES);
    NSString *docs = dirs.count ? dirs[0] : NSTemporaryDirectory();
    return [docs stringByAppendingPathComponent:@"XMLFuzz"];
}

static void write_none(NSString *path, NSData *data)
{
    int fd = open(path.fileSystemRepresentation,
                  O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd >= 0) {
        if (data.length) write(fd, data.bytes, data.length);
        fsync(fd);
        close(fd);
    }
    [[NSFileManager defaultManager] setAttributes:
        @{NSFileProtectionKey: NSFileProtectionNone}
        ofItemAtPath:path error:NULL];
}

static io_connect_t g_surfConn = 0;

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
    if (g_surfConn) return 0;
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
    log_write(@"iogpu: F1 surface sel0=0x%x sid=%u", kr, sid);
    if (kr != KERN_SUCCESS || !sid) {
        IOServiceClose(conn);
        return 0;
    }
    g_surfConn = conn;
    return sid;
}

static size_t pick_size(uint32_t declared)
{
    static const size_t sizes[] = { 0, 4, 8, 0xc, 0x10, 0x18, 0x20, 0x40,
                                    0x100, 0x400, 0x1000, 0x2000 };
    if (declared != 0xffffffff && declared <= 0x2000) return declared;
    return sizes[rnd64() % (sizeof(sizes) / sizeof(sizes[0]))];
}

static void replay_last_iogpu(io_connect_t conn)
{
    NSString *path = [dump_dir() stringByAppendingPathComponent:@"last_iogpu.bin"];
    NSData *d = [NSData dataWithContentsOfFile:path];
    if (!d || d.length == 0) return;
    NSData *mark = [@"input:\n" dataUsingEncoding:NSUTF8StringEncoding];
    NSRange r = [d rangeOfData:mark options:0 range:NSMakeRange(0, d.length)];
    if (r.location == NSNotFound) return;
    NSString *head = [[NSString alloc] initWithData:
                      [d subdataWithRange:NSMakeRange(0, r.location)]
                                            encoding:NSUTF8StringEncoding];
    if (!head) return;
    uint32_t sel = 0, sc = 0;
    size_t len = 0;
    uint64_t scalars[8] = {0};
    for (NSString *line in [head componentsSeparatedByString:@"\n"]) {
        if ([line hasPrefix:@"iter="]) {
            unsigned long long it = 0;
            sscanf(line.UTF8String, "iter=%llu sel=%u sc=%u len=0x%zx",
                   &it, &sel, &sc, &len);
        } else if ([line hasPrefix:@"scalar["]) {
            unsigned int idx = 0;
            unsigned long long v = 0;
            if (sscanf(line.UTF8String, "scalar[%u]=0x%llx", &idx, &v) == 2 && idx < 8)
                scalars[idx] = v;
        }
    }
    if (sc > 8) sc = 8;
    size_t avail = d.length - (r.location + r.length);
    if (len > avail) len = avail;
    NSData *input = [d subdataWithRange:NSMakeRange(r.location + r.length, len)];

    log_write(@"replay iogpu: sel=%u sc=%u len=0x%zx", sel, sc, len);
    ui_update([NSString stringWithFormat:@"replay iogpu sel=%u len=0x%zx", sel, len]);
    uint8_t *out = calloc(1, 0x4000);
    size_t outSize = 0x4000;
    kern_return_t kr = IOConnectCallMethod(conn, sel, sc ? scalars : NULL, sc,
                                           len ? input.bytes : NULL, len,
                                           NULL, NULL, out, &outSize);
    log_write(@"replay iogpu: -> 0x%x out=0x%zx", kr, outSize);
    ui_update([NSString stringWithFormat:@"replay iogpu -> 0x%x", kr]);
    free(out);
}

void iogpu_fuzz(void)
{
    log_write(@"=== IOGPU fuzz start ===");
    ui_update(@"IOGPU fuzz starting...");

    // Create the surface before opening AGX: the user client snapshots the
    // surface table at open, and a later surface is not visible to it.
    IOSurfaceID sid = create_f1_surface();
    IOSurfaceRef surf = sid ? IOSurfaceLookup(sid) : NULL;
    if (!sid) {
        NSDictionary *sp = @{
            @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
            @"IOSurfaceBytesPerElement": @4,
            @"IOSurfacePixelFormat": @0x42475241
        };
        surf = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
        sid = surf ? IOSurfaceGetID(surf) : 0;
    }
    log_write(@"iogpu: surface=%p sid=%u", surf, sid);

    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                   IOServiceMatching("AGXAcceleratorG14P"));
    if (svc == IO_OBJECT_NULL) {
        log_write(@"iogpu: AGXAcceleratorG14P absent");
        return;
    }
    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) {
        log_write(@"iogpu: IOServiceOpen kr=0x%x", kr);
        return;
    }
    log_write(@"iogpu: conn=0x%x", conn);

    // Exact F1 baseline: all fields zero, type 0x82, valid surface.
    {
        uint8_t base[0x100];
        memset(base, 0, sizeof(base));
        *(uint32_t *)(base + 0x00) = 0x82;
        *(uint32_t *)(base + 0x34) = 0;
        *(uint32_t *)(base + 0x38) = sid;
        *(uint32_t *)(base + 0x3c) = 0;
        uint8_t out[0x1000];
        memset(out, 0, sizeof(out));
        size_t outSize = sizeof(out);
        kern_return_t bkr = IOConnectCallMethod(conn, 8, NULL, 0, base, sizeof(base),
                                                NULL, NULL, out, &outSize);
        uint64_t bva = outSize >= 8 ? *(uint64_t *)(out + 0x00) : 0;
        uint64_t blen = outSize >= 0x30 ? *(uint64_t *)(out + 0x28) : 0;
        log_write(@"iogpu: baseline sel8=0x%x va=0x%llx len=0x%llx out=0x%zx",
                  bkr, (unsigned long long)bva, (unsigned long long)blen, outSize);
        ui_update([NSString stringWithFormat:@"IOGPU baseline sel8=0x%x", bkr]);
    }

    replay_last_iogpu(conn);

    uint8_t *in = calloc(1, 0x4000);
    uint8_t *out = calloc(1, 0x4000);
    uint64_t scalars[8];
    NSString *dir = dump_dir();
    uint64_t accepted = 0, errors = 0;

    for (uint64_t it = 0; ; it++) {
        uint32_t sel;
        uint32_t sc;
        size_t len;
        memset(in, 0, 0x4000);
        for (uint32_t i = 0; i < 8; i++) scalars[i] = 0;

        if (surf && ((rnd64() >> 32) & 15) != 0) {
            // Targeted new_resource: mostly the valid type 0x82 path.
            static const uint32_t types[] = {
                0x00, 0x01, 0x02, 0x03, 0x40, 0x80, 0x81, 0x83, 0xff
            };
            sel = 8;
            sc = 0;
            len = 0x100;
            uint32_t type = 0x82;
            if (((rnd64() >> 32) % 10) == 0) {
                type = types[(rnd64() >> 32) % (sizeof(types) / sizeof(types[0]))];
            }
            // Keep the F1 baseline valid; mutate one field at a time.
            memset(in, 0, 0x100);
            *(uint32_t *)(in + 0x00) = type;
            *(uint32_t *)(in + 0x34) = 0;
            *(uint32_t *)(in + 0x38) = sid;
            *(uint32_t *)(in + 0x3c) = 0;
            switch ((rnd64() >> 33) % 8) {
            case 0: *(uint64_t *)(in + 0x40) = rnd64(); break;
            case 1: *(uint32_t *)(in + 0x30) = (uint32_t)rnd64(); break;
            case 2: *(uint64_t *)(in + 0x48) = rnd64(); break;
            case 3: *(uint64_t *)(in + 0x18) = rnd64(); break;
            case 4: *(uint64_t *)(in + 0x20) = rnd64(); break;
            case 5: *(uint64_t *)(in + 0x28) = rnd64(); break;
            case 6: *(uint32_t *)(in + 0x14) = (uint32_t)rnd64(); break;
            default: break; // exact F1 baseline
            }
        } else {
            sel = (uint32_t)(rnd64() % 56);
            if ((rnd64() & 3) == 0) {
                static const uint32_t hot[] = { 6, 8, 25, 38, 39, 42, 45, 46, 52, 53 };
                sel = hot[rnd64() % (sizeof(hot) / sizeof(hot[0]))];
            }
            sc = kSi[sel];
            if (sc > 8) sc = 8;
            len = pick_size(kSzi[sel]);
            if (len > 0x4000) len = 0x4000;
            for (size_t i = 0; i < len; i++) in[i] = (uint8_t)rnd64();
            for (uint32_t i = 0; i < 8; i++) scalars[i] = rnd64();
            if ((rnd64() & 1) == 0) scalars[0] = 0;
        }

        NSMutableString *meta = [NSMutableString string];
        [meta appendFormat:@"iter=%llu sel=%u sc=%u len=0x%zx\n", it, sel, sc, len];
        for (uint32_t i = 0; i < sc; i++)
            [meta appendFormat:@"scalar[%u]=0x%llx\n", i, (unsigned long long)scalars[i]];
        [meta appendString:@"input:\n"];
        NSMutableData *md = [[meta dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        [md appendBytes:in length:len];
        write_none([dir stringByAppendingPathComponent:@"last_iogpu.bin"], md);

        memset(out, 0, 0x4000);
        size_t outSize = 0x4000;
        kr = IOConnectCallMethod(conn, sel, sc ? scalars : NULL, sc,
                                 len ? in : NULL, len,
                                 NULL, NULL, out, &outSize);
        if (kr == KERN_SUCCESS) {
            accepted++;
            if (outSize >= 0x30) {
                uint64_t va = *(uint64_t *)(out + 0x00);
                uint64_t len = *(uint64_t *)(out + 0x28);
                if (va != 0x1500000000ULL || len != 0x10000ULL) {
                    log_write(@"iogpu: SUCCESS it=%llu sel=%u va=0x%llx len=0x%llx",
                              it, sel, (unsigned long long)va,
                              (unsigned long long)len);
                }
            }
        } else {
            errors++;
        }

        if (kr != KERN_SUCCESS && kr != (kern_return_t)0xe00002c2 &&
            kr != (kern_return_t)0xe00002bc && kr != (kern_return_t)0xe00002c7 &&
            kr != (kern_return_t)0xe00002d8) {
            log_write(@"iogpu: it=%llu sel=%u sc=%u len=0x%zx kr=0x%x out=0x%zx",
                      it, sel, sc, len, kr, outSize);
        }
        if ((it & 0xff) == 0 && it != 0) {
            IOServiceClose(conn);
            io_service_t svc2 = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                            IOServiceMatching("AGXAcceleratorG14P"));
            conn = IO_OBJECT_NULL;
            if (svc2 != IO_OBJECT_NULL) {
                IOServiceOpen(svc2, mach_task_self(), 1, &conn);
                IOObjectRelease(svc2);
            }
            log_write(@"iogpu: reconnect it=%llu conn=0x%x", it, conn);
            if (!conn) break;
        }
        if ((it & 0x3ff) == 0) {
            log_write(@"iogpu: it=%llu sel=%u kr=0x%x accepted=%llu errors=%llu",
                      it, sel, kr, accepted, errors);
            ui_update([NSString stringWithFormat:
                @"IOGPU fuzz\niter=%llu sel=%u\nkr=0x%x\naccepted=%llu errors=%llu\nlog=%@",
                it, sel, kr, accepted, errors, log_path()]);
        }
        usleep(3000);
    }
}
