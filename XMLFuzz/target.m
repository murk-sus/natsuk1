#import "target.h"
#import "fuzz.h"
#import "logger.h"
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#import <dlfcn.h>
#import <string.h>
#import <unistd.h>
#import <fcntl.h>
#import <sys/mman.h>

typedef struct {
    uint64_t alloc;
    uint64_t psize;
    uint32_t slices;
    uint32_t dataPer;
    uint32_t headerPer;
    uint32_t comp;
    uint32_t hdrOff;
    uint32_t dataOff;
} tshape_t;

typedef void *IOSurfaceAcceleratorRef;
typedef kern_return_t (*AccelCreateFn)(CFAllocatorRef, uint32_t, IOSurfaceAcceleratorRef *);
typedef kern_return_t (*AccelTransferFn)(IOSurfaceAcceleratorRef, IOSurfaceRef,
                                         IOSurfaceRef, CFDictionaryRef, void *);

static NSArray *g_uiLines = nil;

static NSString *target_xml(const tshape_t *s)
{
    NSMutableString *x = [NSMutableString stringWithCapacity:2048];
    [x appendString:@"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict>"];
    [x appendString:@"<key>IOSurfaceWidth</key><integer>64</integer>"
        "<key>IOSurfaceHeight</key><integer>64</integer>"
        "<key>IOSurfaceBytesPerElement</key><integer>4</integer>"
        "<key>IOSurfacePixelFormat</key><integer>1111970369</integer>"];
    [x appendFormat:@"<key>IOSurfaceAllocSize</key><integer>%llu</integer>", s->alloc];
    [x appendFormat:@"<key>IOSurfaceSliceCount</key><integer>%u</integer>", s->slices];
    [x appendString:@"<key>IOSurfacePlaneInfo</key><array><dict>"
        "<key>IOSurfacePlaneWidth</key><integer>64</integer>"
        "<key>IOSurfacePlaneHeight</key><integer>64</integer>"
        "<key>IOSurfacePlaneBytesPerElement</key><integer>4</integer>"
        "<key>IOSurfacePlaneBytesPerRow</key><integer>512</integer>"];
    [x appendFormat:@"<key>IOSurfacePlaneSize</key><integer>%llu</integer>", s->psize];
    [x appendFormat:@"<key>IOSurfacePlaneCompressionType</key><integer>%u</integer>", s->comp];
    [x appendFormat:@"<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>%u</integer>", s->dataPer];
    [x appendFormat:@"<key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>%u</integer>", s->headerPer];
    [x appendString:@"<key>IOSurfacePlaneCompressedTileWidth</key><integer>32</integer>"
        "<key>IOSurfacePlaneCompressedTileHeight</key><integer>32</integer>"
        "<key>IOSurfacePlaneBytesPerCompressedTileHeader</key><integer>8</integer>"
        "<key>IOSurfacePlaneBytesPerTileData</key><integer>4096</integer>"
        "<key>IOSurfacePlaneWidthInCompressedTiles</key><integer>2</integer>"
        "<key>IOSurfacePlaneHeightInCompressedTiles</key><integer>2</integer>"
        "<key>IOSurfacePlaneBytesPerRowOfTileData</key><integer>8192</integer>"];
    [x appendFormat:@"<key>IOSurfacePlaneCompressedTileHeaderRegionOffset</key><integer>%u</integer>", s->hdrOff];
    [x appendFormat:@"<key>IOSurfacePlaneCompressedTileDataRegionOffset</key><integer>%u</integer>", s->dataOff];
    [x appendString:@"<key>IOSurfacePlaneBytesPerRowOfCompressedTileHeaderGroups</key><integer>0</integer>"
        "</dict></array></dict></plist>\n"];
    return x;
}

static void ui_add(NSString *line)
{
    NSString *all = line;
    if (g_uiLines) {
        NSMutableArray *a = [g_uiLines mutableCopy];
        [a addObject:line];
        if (a.count > 18) [a removeObjectsInRange:NSMakeRange(0, a.count - 18)];
        all = [a componentsJoinedByString:@"\n"];
    }
    ui_update(all);
}

static void probe_surface(uint32_t sid, NSString *tag)
{
    log_write(@"%@: lookup sid=%u", tag, sid);
    IOSurfaceRef s = IOSurfaceLookup(sid);
    if (!s) {
        log_write(@"%@: lookup failed", tag);
        return;
    }
    void *base = IOSurfaceGetBaseAddress(s);
    size_t alloc = IOSurfaceGetAllocSize(s);
    size_t planes = IOSurfaceGetPlaneCount(s);
    log_write(@"%@: sid=%u base=%p alloc=0x%zx planes=%zu",
              tag, sid, base, alloc, planes);
    ui_add([NSString stringWithFormat:@"%@: base=%p alloc=0x%zx planes=%zu",
            tag, base, alloc, planes]);

    log_write(@"%@: IOSurfaceLock begin", tag);
    kern_return_t lk = IOSurfaceLock(s, 0, NULL);
    log_write(@"%@: IOSurfaceLock -> 0x%x", tag, lk);
    ui_add([NSString stringWithFormat:@"%@: lock=0x%x", tag, lk]);
    if (lk == KERN_SUCCESS) IOSurfaceUnlock(s, 0, NULL);

    for (size_t p = 0; p < planes && p < 2; p++) {
        log_write(@"%@: plane[%zu] getters begin", tag, p);
        void *pb = IOSurfaceGetBaseAddressOfPlane(s, p);
        size_t bpr = IOSurfaceGetBytesPerRowOfPlane(s, p);
        size_t w = IOSurfaceGetWidthOfPlane(s, p);
        size_t h = IOSurfaceGetHeightOfPlane(s, p);
        log_write(@"%@: plane[%zu] base=%p bpr=0x%zx w=%zu h=%zu",
                  tag, p, pb, bpr, w, h);
        ui_add([NSString stringWithFormat:@"%@: plane%zu base=%p bpr=0x%zx",
                tag, p, pb, bpr]);
    }
    CFRelease(s);
}

static void accel_probe(IOSurfaceRef surf, NSString *tag)
{
    void *h = dlopen("/System/Library/PrivateFrameworks/IOSurfaceAccelerator.framework/IOSurfaceAccelerator", RTLD_LAZY);
    if (!h) {
        log_write(@"%@: accel dlopen failed: %s", tag, dlerror());
        return;
    }
    AccelCreateFn create = (AccelCreateFn)dlsym(h, "IOSurfaceAcceleratorCreate");
    AccelTransferFn transfer = (AccelTransferFn)dlsym(h, "IOSurfaceAcceleratorTransferSurface");
    if (!create || !transfer) {
        log_write(@"%@: accel symbols missing", tag);
        dlclose(h);
        return;
    }
    IOSurfaceAcceleratorRef accel = NULL;
    kern_return_t kr = create(kCFAllocatorDefault, 0, &accel);
    log_write(@"%@: accel create -> 0x%x accel=%p", tag, kr, accel);
    if (kr != KERN_SUCCESS || !accel) { dlclose(h); return; }

    NSDictionary *props = @{
        @"IOSurfaceWidth": @64, @"IOSurfaceHeight": @64,
        @"IOSurfaceBytesPerElement": @4,
        @"IOSurfacePixelFormat": @0x42475241
    };
    IOSurfaceRef dst = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (dst) {
        log_write(@"%@: accel transfer begin dst=%p", tag, dst);
        kr = transfer(accel, surf, dst, NULL, NULL);
        log_write(@"%@: accel transfer -> 0x%x", tag, kr);
        ui_add([NSString stringWithFormat:@"%@: accel transfer=0x%x", tag, kr]);
        CFRelease(dst);
    }
    dlclose(h);
}

static void sel8_address_test(io_connect_t conn, IOSurfaceID sid)
{
    void *u = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (u != MAP_FAILED) memset(u, 0xAB, 0x4000);

    const uint64_t addrs[2] = { (uint64_t)(uintptr_t)u, 0xfffffff007004000ULL };
    const char *names[2] = { "user", "kern" };
    const uint32_t types[3] = { 0, 0x80, 0x82 };

    for (int ti = 0; ti < 3; ti++) {
        for (int ai = 0; ai < 2; ai++) {
            uint8_t in[0x100];
            memset(in, 0, sizeof(in));
            *(uint32_t *)(in + 0x00) = types[ti];
            *(uint64_t *)(in + 0x18) = addrs[ai];
            *(uint64_t *)(in + 0x20) = addrs[ai];
            *(uint64_t *)(in + 0x28) = 0x4000;
            *(uint32_t *)(in + 0x30) = 1;
            *(uint32_t *)(in + 0x34) = 0;
            *(uint32_t *)(in + 0x38) = sid;
            *(uint32_t *)(in + 0x3c) = 0;
            *(uint64_t *)(in + 0x40) = 0x4000;
            *(uint64_t *)(in + 0x48) = 0x4000;
            *(uint32_t *)(in + 0x50) = 0;

            uint8_t out[0x1000];
            memset(out, 0, sizeof(out));
            size_t outSize = sizeof(out);
            log_write(@"sel8addr: type=0x%x addr=%s:0x%llx len=0x4000",
                      types[ti], names[ai], (unsigned long long)addrs[ai]);
            ui_add([NSString stringWithFormat:@"sel8addr type=0x%x %s",
                    types[ti], names[ai]]);
            kern_return_t kr = IOConnectCallMethod(conn, 8, NULL, 0, in, sizeof(in),
                                                   NULL, NULL, out, &outSize);
            uint64_t o0 = outSize >= 8 ? *(uint64_t *)(out + 0x00) : 0;
            uint64_t o28 = outSize >= 0x30 ? *(uint64_t *)(out + 0x28) : 0;
            uint64_t o50 = outSize >= 0x58 ? *(uint64_t *)(out + 0x50) : 0;
            log_write(@"sel8addr: -> 0x%x out=0x%zx va=0x%llx len=0x%llx o50=0x%llx",
                      kr, outSize, (unsigned long long)o0,
                      (unsigned long long)o28, (unsigned long long)o50);
            ui_add([NSString stringWithFormat:@"sel8addr -> 0x%x va=0x%llx", kr, o0]);
        }
    }
    if (u != MAP_FAILED) munmap(u, 0x4000);
}

static void sel8_value_sweep(io_connect_t conn, IOSurfaceID sid)
{
    static const uint64_t vals[] = {
        0, 1, 2, 3, 4, 8, 0x10, 0x100, 0x1000, 0x10000,
        0x7fffffff, 0x80000000, 0xffffffffULL,
        0x100000000ULL, 0xffffffffffffffffULL
    };
    for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
        uint8_t in[0x100];
        memset(in, 0, sizeof(in));
        *(uint32_t *)(in + 0x00) = 0x82;
        *(uint32_t *)(in + 0x38) = sid;
        *(uint32_t *)(in + 0x3c) = 0;
        *(uint64_t *)(in + 0x40) = vals[i];

        uint8_t out[0x1000];
        memset(out, 0, sizeof(out));
        size_t outSize = sizeof(out);
        log_write(@"sel8val: +0x40=0x%llx", (unsigned long long)vals[i]);
        ui_add([NSString stringWithFormat:@"sel8val +0x40=0x%llx",
                (unsigned long long)vals[i]]);
        kern_return_t kr = IOConnectCallMethod(conn, 8, NULL, 0, in, sizeof(in),
                                               NULL, NULL, out, &outSize);
        uint64_t o0 = outSize >= 8 ? *(uint64_t *)(out + 0x00) : 0;
        uint64_t o28 = outSize >= 0x30 ? *(uint64_t *)(out + 0x28) : 0;
        uint64_t o50 = outSize >= 0x58 ? *(uint64_t *)(out + 0x50) : 0;
        log_write(@"sel8val: -> 0x%x out=0x%zx va=0x%llx len=0x%llx o50=0x%llx",
                  kr, outSize, (unsigned long long)o0,
                  (unsigned long long)o28, (unsigned long long)o50);
        ui_add([NSString stringWithFormat:@"sel8val -> 0x%x va=0x%llx", kr, o0]);
    }
}

static void sel8_field_sweep(io_connect_t conn, IOSurfaceID sid)
{
    static const uint32_t counts[] = {
        0, 1, 2, 3, 4, 8, 0x10, 0x100, 0x1000, 0xffffffff
    };
    for (size_t i = 0; i < sizeof(counts)/sizeof(counts[0]); i++) {
        uint8_t in[0x100];
        memset(in, 0, sizeof(in));
        *(uint32_t *)(in + 0x00) = 0x82;
        *(uint32_t *)(in + 0x30) = counts[i];
        *(uint32_t *)(in + 0x38) = sid;
        *(uint32_t *)(in + 0x3c) = 0;
        *(uint64_t *)(in + 0x48) = 0x4000;
        uint8_t out[0x1000];
        memset(out, 0, sizeof(out));
        size_t outSize = sizeof(out);
        log_write(@"sel8cnt: +0x30=0x%x", counts[i]);
        kern_return_t kr = IOConnectCallMethod(conn, 8, NULL, 0, in, sizeof(in),
                                               NULL, NULL, out, &outSize);
        uint64_t o0 = outSize >= 8 ? *(uint64_t *)(out + 0x00) : 0;
        uint64_t o50 = outSize >= 0x58 ? *(uint64_t *)(out + 0x50) : 0;
        log_write(@"sel8cnt: -> 0x%x va=0x%llx o50=0x%llx",
                  kr, (unsigned long long)o0, (unsigned long long)o50);
        ui_add([NSString stringWithFormat:@"sel8cnt 0x%x -> 0x%x", counts[i], kr]);
    }

    static const uint64_t wires[] = {
        0, 0x4000, 0x10000, 0x100000, 0x1000000, 0xffffffffULL,
        0xffffffffffffffffULL
    };
    for (size_t i = 0; i < sizeof(wires)/sizeof(wires[0]); i++) {
        uint8_t in[0x100];
        memset(in, 0, sizeof(in));
        *(uint32_t *)(in + 0x00) = 0x82;
        *(uint32_t *)(in + 0x30) = 1;
        *(uint32_t *)(in + 0x38) = sid;
        *(uint32_t *)(in + 0x3c) = 0;
        *(uint64_t *)(in + 0x48) = wires[i];
        uint8_t out[0x1000];
        memset(out, 0, sizeof(out));
        size_t outSize = sizeof(out);
        log_write(@"sel8wire: +0x48=0x%llx", (unsigned long long)wires[i]);
        kern_return_t kr = IOConnectCallMethod(conn, 8, NULL, 0, in, sizeof(in),
                                               NULL, NULL, out, &outSize);
        uint64_t o0 = outSize >= 8 ? *(uint64_t *)(out + 0x00) : 0;
        uint64_t o50 = outSize >= 0x58 ? *(uint64_t *)(out + 0x50) : 0;
        log_write(@"sel8wire: -> 0x%x va=0x%llx o50=0x%llx",
                  kr, (unsigned long long)o0, (unsigned long long)o50);
        ui_add([NSString stringWithFormat:@"sel8wire 0x%llx -> 0x%x",
                (unsigned long long)wires[i], kr]);
    }
}

static void reconnect_test(IOSurfaceID sid)
{
    for (int i = 0; i < 24; i++) {
        io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                       IOServiceMatching("AGXAcceleratorG14P"));
        io_connect_t ac = 0;
        if (svc != IO_OBJECT_NULL) {
            IOServiceOpen(svc, mach_task_self(), 1, &ac);
            IOObjectRelease(svc);
        }
        log_write(@"reconnect[%d]: open conn=0x%x", i, ac);
        ui_add([NSString stringWithFormat:@"reconnect[%d] open=0x%x", i, ac]);
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
        log_write(@"reconnect[%d]: call", i);
        kern_return_t kr = IOConnectCallMethod(ac, 8, NULL, 0, in, sizeof(in),
                                               NULL, NULL, out, &outSize);
        uint64_t va = outSize >= 8 ? *(uint64_t *)(out + 0x00) : 0;
        uint64_t len = outSize >= 0x30 ? *(uint64_t *)(out + 0x28) : 0;
        log_write(@"reconnect[%d]: -> 0x%x va=0x%llx len=0x%llx",
                  i, kr, (unsigned long long)va, (unsigned long long)len);
        ui_add([NSString stringWithFormat:@"reconnect[%d] -> 0x%x", i, kr]);
        IOServiceClose(ac);
        log_write(@"reconnect[%d]: close", i);
        usleep(50000);
    }
    log_write(@"reconnect: done");
}

static IOSurfaceID make_f1_sid(io_connect_t conn)
{
    tshape_t s;
    s.alloc = 0x10000;
    s.psize = 0x10000;
    s.slices = 4;
    s.dataPer = 0x4000;
    s.headerPer = 0x40000000;
    s.comp = 4;
    s.hdrOff = 0x10000;
    s.dataOff = 0;
    NSString *xml = target_xml(&s);
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
    log_write(@"target: F1 shape sel0=0x%x sid=%u", kr, sid);
    ui_add([NSString stringWithFormat:@"F1 shape sel0=0x%x sid=%u", kr, sid]);
    return (kr == KERN_SUCCESS) ? sid : 0;
}

static void sel8_suballoc_test(io_connect_t conn, IOSurfaceID sid)
{
    // Create a parent resource from the F1 surface.
    uint8_t in[0x100];
    memset(in, 0, sizeof(in));
    *(uint32_t *)(in + 0x00) = 0x82;
    *(uint32_t *)(in + 0x38) = sid;
    *(uint32_t *)(in + 0x3c) = 0;
    uint8_t out[0x1000];
    memset(out, 0, sizeof(out));
    size_t outSize = sizeof(out);
    kern_return_t kr = IOConnectCallMethod(conn, 8, NULL, 0, in, sizeof(in),
                                           NULL, NULL, out, &outSize);
    uint32_t parent = outSize >= 0x38 ? *(uint32_t *)(out + 0x30) : 0;
    uint64_t pva = outSize >= 8 ? *(uint64_t *)(out + 0x00) : 0;
    uint64_t plen = outSize >= 0x30 ? *(uint64_t *)(out + 0x28) : 0;
    log_write(@"suballoc: parent sel8=0x%x id=0x%x va=0x%llx len=0x%llx",
              kr, parent, (unsigned long long)pva, (unsigned long long)plen);
    ui_add([NSString stringWithFormat:@"suballoc parent id=0x%x", parent]);

    uint32_t ids[] = { parent, parent + 1, parent - 1, 0, 1, 2, 3, 4, 0xffffffff };
    const uint32_t types[] = { 0, 0x80, 0x82 };
    for (size_t ii = 0; ii < sizeof(ids)/sizeof(ids[0]); ii++) {
        for (size_t ti = 0; ti < sizeof(types)/sizeof(types[0]); ti++) {
            uint8_t sub[0x100];
            memset(sub, 0, sizeof(sub));
            *(uint32_t *)(sub + 0x00) = types[ti];
            *(uint32_t *)(sub + 0x38) = sid;
            *(uint32_t *)(sub + 0x3c) = 0;
            *(uint64_t *)(sub + 0x18) = 0;
            *(uint64_t *)(sub + 0x40) = 0x1000;
            *(uint64_t *)(sub + 0x48) = 0x1000;
            *(uint32_t *)(sub + 0x50) = ids[ii];
            *(uint32_t *)(sub + 0x14) = 0x800; // byte +0x15 bit 3: suballocation flag
            uint8_t so[0x1000];
            memset(so, 0, sizeof(so));
            size_t soSize = sizeof(so);
            log_write(@"suballoc: type=0x%x parent=0x%x", types[ti], ids[ii]);
            kern_return_t r = IOConnectCallMethod(conn, 8, NULL, 0, sub, sizeof(sub),
                                                  NULL, NULL, so, &soSize);
            uint64_t va = soSize >= 8 ? *(uint64_t *)(so + 0x00) : 0;
            uint64_t len = soSize >= 0x30 ? *(uint64_t *)(so + 0x28) : 0;
            log_write(@"suballoc: -> 0x%x out=0x%zx va=0x%llx len=0x%llx",
                      r, soSize, (unsigned long long)va, (unsigned long long)len);
            ui_add([NSString stringWithFormat:@"suballoc type=0x%x p=0x%x -> 0x%x",
                    types[ti], ids[ii], r]);
        }
    }
}

static void sel8_texture_and_suballoc(io_connect_t conn)
{
    void *u = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (u == MAP_FAILED) return;
    memset(u, 0x5A, 0x4000);

    // Type 0: standard texture from a user buffer.
    uint8_t in[0x100];
    memset(in, 0, sizeof(in));
    *(uint32_t *)(in + 0x00) = 0;
    *(uint64_t *)(in + 0x18) = (uint64_t)(uintptr_t)u;
    *(uint64_t *)(in + 0x48) = 0x4000;
    uint8_t out[0x1000];
    memset(out, 0, sizeof(out));
    size_t outSize = sizeof(out);
    log_write(@"tex: type=0 addr=%p len=0x4000", u);
    kern_return_t kr = IOConnectCallMethod(conn, 8, NULL, 0, in, sizeof(in),
                                           NULL, NULL, out, &outSize);
    uint32_t parent = outSize >= 0x38 ? *(uint32_t *)(out + 0x30) : 0;
    log_write(@"tex: -> 0x%x parent=0x%x out=0x%zx", kr, parent, outSize);
    ui_add([NSString stringWithFormat:@"tex type=0 -> 0x%x parent=0x%x", kr, parent]);
    if (kr != KERN_SUCCESS || !parent) { munmap(u, 0x4000); return; }

    for (int ti = 0; ti < 2; ti++) {
        uint32_t type = ti ? 0x80 : 0;
        uint8_t sub[0x100];
        memset(sub, 0, sizeof(sub));
        *(uint32_t *)(sub + 0x00) = type;
        *(uint32_t *)(sub + 0x14) = 0x800; // suballocation flag
        *(uint32_t *)(sub + 0x50) = parent;
        if (type == 0) {
            *(uint64_t *)(sub + 0x48) = 0x1000;
        } else {
            *(uint64_t *)(sub + 0x38) = 0x1000;
            *(uint64_t *)(sub + 0x40) = 0x100;
            *(uint64_t *)(sub + 0x48) = 0x1000;
        }
        uint8_t so[0x1000];
        memset(so, 0, sizeof(so));
        size_t soSize = sizeof(so);
        log_write(@"subtex: type=0x%x parent=0x%x", type, parent);
        kern_return_t r = IOConnectCallMethod(conn, 8, NULL, 0, sub, sizeof(sub),
                                              NULL, NULL, so, &soSize);
        uint64_t va = soSize >= 8 ? *(uint64_t *)(so + 0x00) : 0;
        uint64_t len = soSize >= 0x30 ? *(uint64_t *)(so + 0x28) : 0;
        log_write(@"subtex: -> 0x%x va=0x%llx len=0x%llx",
                  r, (unsigned long long)va, (unsigned long long)len);
        ui_add([NSString stringWithFormat:@"subtex type=0x%x -> 0x%x", type, r]);
    }
    munmap(u, 0x4000);
}

static void replay_last(io_connect_t conn)
{
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                        NSUserDomainMask, YES);
    NSString *docs = dirs.count ? dirs[0] : NSTemporaryDirectory();
    NSString *path = [docs stringByAppendingPathComponent:@"XMLFuzz/last.xml"];
    NSData *d = [NSData dataWithContentsOfFile:path];
    if (!d || d.length == 0) {
        log_write(@"replay: no last.xml");
        return;
    }
    NSMutableData *call = [d mutableCopy];
    uint8_t nul = 0;
    [call appendBytes:&nul length:1];
    log_write(@"replay: last.xml len=%zu", d.length);
    ui_add([NSString stringWithFormat:@"replay last.xml len=%zu", d.length]);

    uint8_t out[0xc68];
    memset(out, 0, sizeof(out));
    uint64_t sc[1] = {0};
    size_t outSize = sizeof(out);
    kern_return_t kr = IOConnectCallMethod(conn, 0, sc, 1, call.bytes, call.length,
                                           NULL, NULL, out, &outSize);
    uint32_t sid = outSize >= 0x1c ? *(uint32_t *)(out + 0x18) : 0;
    log_write(@"replay: sel0 -> 0x%x sid=%u out=0x%zx", kr, sid, outSize);
    ui_add([NSString stringWithFormat:@"replay sel0=0x%x sid=%u", kr, sid]);
    if (kr == KERN_SUCCESS && sid) {
        probe_surface(sid, @"replay");
        IOSurfaceRef sref = IOSurfaceLookup(sid);
        if (sref) {
            accel_probe(sref, @"replay");
            CFRelease(sref);
        }
    }
}

void target_run(void)
{
    log_start();
    log_write(@"=== XMLTarget start ===");
    ui_add(@"XMLTarget start");

    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                   IOServiceMatching("IOSurfaceRoot"));
    if (svc == IO_OBJECT_NULL) {
        log_write(@"target: IOSurfaceRoot absent");
        return;
    }
    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) {
        log_write(@"target: IOServiceOpen kr=0x%x", kr);
        return;
    }
    log_write(@"target: IOSurfaceRoot conn=0x%x", conn);
    replay_last(conn);

    IOSurfaceID f1sid = make_f1_sid(conn);
    if (f1sid) reconnect_test(f1sid);
    io_service_t agxSvc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                      IOServiceMatching("AGXAcceleratorG14P"));
    io_connect_t agxConn = 0;
    if (agxSvc != IO_OBJECT_NULL) {
        IOServiceOpen(agxSvc, mach_task_self(), 1, &agxConn);
        IOObjectRelease(agxSvc);
    }
    log_write(@"target: AGX conn=0x%x f1sid=%u", agxConn, f1sid);
    if (f1sid && agxConn) {
        sel8_address_test(agxConn, f1sid);
        sel8_value_sweep(agxConn, f1sid);
        sel8_field_sweep(agxConn, f1sid);
        sel8_suballoc_test(agxConn, f1sid);
        sel8_texture_and_suballoc(agxConn);
    }
    if (agxConn) IOServiceClose(agxConn);

    // The 64-bit planeSize matrix is negative and the huge declared sizes
    // can OOM the app before the IOGPU fuzzer starts.  Skip it; the F1
    // replay + sel8 sweeps above are the useful deterministic tests.
    IOServiceClose(conn);
    log_write(@"=== XMLTarget sweeps done; planeSize matrix skipped ===");
    ui_add(@"target sweeps done; IOGPU fuzz next");
    return;

    static const uint64_t allocs[] = { 0x10000, 0x4000, 0x1000 };
    static const uint64_t psizes[] = {
        0x100010000ULL, 0x100000000ULL, 0xffffffffULL,
        0x7fffffffffffffffULL, 0x8000000000000000ULL,
        0xffffffffffffffffULL, 0x1000000000ULL,
    };
    static const uint32_t headers[] = { 0x40000000, 0x3fffc000, 0x80000000 };

    uint8_t out[0xc68];
    int idx = 0;

    for (size_t ai = 0; ai < sizeof(allocs)/sizeof(allocs[0]); ai++) {
        for (size_t pi = 0; pi < sizeof(psizes)/sizeof(psizes[0]); pi++) {
            for (size_t hi = 0; hi < sizeof(headers)/sizeof(headers[0]); hi++) {
                tshape_t s;
                s.alloc = allocs[ai];
                s.psize = psizes[pi];
                s.slices = 4;
                s.dataPer = 0x4000;
                s.headerPer = headers[hi];
                s.comp = 4;
                s.hdrOff = 0x10000;
                s.dataOff = 0;

                NSString *xml = target_xml(&s);
                NSData *xd = [xml dataUsingEncoding:NSUTF8StringEncoding];
                if (!xd || xd.length + 1 > 0x1000) {
                    log_write(@"target[%d]: XML too large %zu", idx, xd.length);
                    continue;
                }
                NSMutableData *call = [NSMutableData dataWithData:xd];
                uint8_t nul = 0;
                [call appendBytes:&nul length:1];

                log_write(@"target[%d]: alloc=0x%llx psize=0x%llx header=0x%x",
                          idx, s.alloc, s.psize, s.headerPer);
                ui_add([NSString stringWithFormat:
                        @"target[%d] alloc=0x%llx psize=0x%llx",
                        idx, s.alloc, s.psize]);

                memset(out, 0, sizeof(out));
                uint64_t sc[1] = {0};
                size_t outSize = sizeof(out);
                kr = IOConnectCallMethod(conn, 0, sc, 1, call.bytes, call.length,
                                         NULL, NULL, out, &outSize);
                uint32_t sid = outSize >= 0x1c ? *(uint32_t *)(out + 0x18) : 0;
                log_write(@"target[%d]: sel0 -> 0x%x sid=%u out=0x%zx",
                          idx, kr, sid, outSize);
                ui_add([NSString stringWithFormat:
                        @"target[%d] sel0=0x%x sid=%u", idx, kr, sid]);

                if (kr == KERN_SUCCESS && sid) {
                    probe_surface(sid, [NSString stringWithFormat:@"target[%d]", idx]);
                    IOSurfaceRef sref = IOSurfaceLookup(sid);
                    if (sref) {
                        accel_probe(sref, [NSString stringWithFormat:@"target[%d]", idx]);
                        CFRelease(sref);
                    }
                }
                idx++;
                usleep(20000);
            }
        }
    }

    log_write(@"=== XMLTarget done (%d shapes) ===", idx);
    ui_add([NSString stringWithFormat:@"XMLTarget done: %d shapes", idx]);
    IOServiceClose(conn);
}
