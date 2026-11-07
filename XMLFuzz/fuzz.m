#import "fuzz.h"
#import "logger.h"
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurfaceRef.h>
#import <string.h>
#import <stdlib.h>
#import <unistd.h>
#import <fcntl.h>
#import <sys/stat.h>

// ---------------------------------------------------------------- PRNG

static uint64_t g_rng = 0x9e3779b97f4a7c15ULL;

static uint64_t rnd64(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return g_rng;
}

static uint32_t rnd32(void) { return (uint32_t)rnd64(); }

static uint32_t pick32(const uint32_t *v, size_t n)
{
    return v[rnd64() % n];
}

static uint32_t rand32(void) { return (uint32_t)rnd64(); }

// ---------------------------------------------------------------- shape

typedef struct {
    uint32_t width, height, bpe, pixfmt, alloc;
    uint32_t slices;
    uint32_t pw, ph, pbpe, pbpr, psize;
    uint32_t comp, dataPer, headerPer;
    uint32_t tileW, tileH, hdrBytes, tileData;
    uint32_t tilesW, tilesH, tileBpr;
    uint32_t hdrOff, dataOff, hdrGroupBpr;
} shape_t;

static const uint32_t kSmall[] = {
    0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 512,
    0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000,
    0x10000, 0x20000, 0x40000, 0x100000,
};

static const uint32_t kBig[] = {
    0x3fffc000, 0x3fffffff, 0x40000000, 0x40000001,
    0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff,
};

static const uint32_t kSlices[] = { 0, 1, 2, 3, 4, 5, 8, 16, 32, 0xffffffff };
static const uint32_t kComp[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 0xffffffff };

static shape_t base_shape(void)
{
    shape_t s;
    s.width = 64;
    s.height = 64;
    s.bpe = 4;
    s.pixfmt = 0x42475241; // 'BGRA'
    s.alloc = 0x10000;
    s.slices = 4;
    s.pw = 64;
    s.ph = 64;
    s.pbpe = 4;
    s.pbpr = 512;
    s.psize = 0x10000;
    s.comp = 4;
    s.dataPer = 0x4000;
    s.headerPer = 0x40000000;
    s.tileW = 32;
    s.tileH = 32;
    s.hdrBytes = 8;
    s.tileData = 0x1000;
    s.tilesW = 2;
    s.tilesH = 2;
    s.tileBpr = 0x2000;
    s.hdrOff = 0x10000;
    s.dataOff = 0;
    s.hdrGroupBpr = 0;
    return s;
}

static void mutate_one(shape_t *s)
{
    uint32_t v;
    switch (rnd32() % 22) {
    case 0: s->width = pick32(kSmall, sizeof(kSmall)/4); break;
    case 1: s->height = pick32(kSmall, sizeof(kSmall)/4); break;
    case 2: s->bpe = pick32(kSmall, sizeof(kSmall)/4); break;
    case 3: s->pixfmt = (rnd32() & 1) ? 0x42475241 : rand32(); break;
    case 4: s->alloc = pick32(kBig, sizeof(kBig)/4); break;
    case 5: s->slices = pick32(kSlices, sizeof(kSlices)/4); break;
    case 6: s->pw = pick32(kSmall, sizeof(kSmall)/4); break;
    case 7: s->ph = pick32(kSmall, sizeof(kSmall)/4); break;
    case 8: s->pbpe = pick32(kSmall, sizeof(kSmall)/4); break;
    case 9: s->pbpr = pick32(kSmall, sizeof(kSmall)/4); break;
    case 10: s->psize = pick32(kBig, sizeof(kBig)/4); break;
    case 11: s->comp = pick32(kComp, sizeof(kComp)/4); break;
    case 12: s->dataPer = pick32(kSmall, sizeof(kSmall)/4); break;
    case 13: s->headerPer = pick32(kBig, sizeof(kBig)/4); break;
    case 14: s->tileW = pick32(kSmall, sizeof(kSmall)/4); break;
    case 15: s->tileH = pick32(kSmall, sizeof(kSmall)/4); break;
    case 16: s->hdrBytes = pick32(kSmall, sizeof(kSmall)/4); break;
    case 17: s->tileData = pick32(kSmall, sizeof(kSmall)/4); break;
    case 18: s->tilesW = pick32(kSmall, sizeof(kSmall)/4); break;
    case 19: s->tilesH = pick32(kSmall, sizeof(kSmall)/4); break;
    case 20: s->tileBpr = pick32(kSmall, sizeof(kSmall)/4); break;
    default:
        v = rand32();
        switch (rnd32() % 4) {
        case 0: s->hdrOff = v; break;
        case 1: s->dataOff = v; break;
        case 2: s->hdrGroupBpr = v; break;
        default: s->headerPer = v; break;
        }
    }
}

static void make_shape(shape_t *s)
{
    *s = base_shape();
    switch (rnd32() % 10) {
    case 0: case 1: case 2: case 3: case 4: case 5:
        // F1 family: keep the 32-bit wrap, mutate secondary fields.
        for (int i = 0, n = 1 + (int)(rnd32() % 3); i < n; i++)
            mutate_one(s);
        break;
    case 6: case 7: case 8: {
        // Wrap family: choose (data + header) * slices mod 2^32 as planeSize.
        s->slices = pick32(kSlices, sizeof(kSlices)/4);
        if (s->slices == 0 || s->slices == 0xffffffff) s->slices = 4;
        s->dataPer = pick32(kSmall, sizeof(kSmall)/4) & 0xffff;
        uint32_t sum = pick32(kBig, sizeof(kBig)/4);
        if ((rnd32() & 1) == 0) sum = 0x40000000u + (rnd32() & 0xffff);
        s->headerPer = sum - s->dataPer;
        s->psize = (s->dataPer + s->headerPer) * s->slices;
        s->alloc = s->psize;
        s->comp = 4;
        for (int i = 0, n = (int)(rnd32() % 3); i < n; i++)
            mutate_one(s);
        break;
    }
    default:
        // Fully random but structured.
        for (int i = 0; i < 6; i++)
            mutate_one(s);
        break;
    }
}

// ---------------------------------------------------------------- XML

static NSString *xml_from_shape(const shape_t *s)
{
    NSMutableString *x = [NSMutableString stringWithCapacity:2048];
    [x appendString:@"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict>"];
    [x appendFormat:@"<key>IOSurfaceWidth</key><integer>%u</integer>", s->width];
    [x appendFormat:@"<key>IOSurfaceHeight</key><integer>%u</integer>", s->height];
    [x appendFormat:@"<key>IOSurfaceBytesPerElement</key><integer>%u</integer>", s->bpe];
    [x appendFormat:@"<key>IOSurfacePixelFormat</key><integer>%u</integer>", s->pixfmt];
    [x appendFormat:@"<key>IOSurfaceAllocSize</key><integer>%u</integer>", s->alloc];
    [x appendFormat:@"<key>IOSurfaceSliceCount</key><integer>%u</integer>", s->slices];
    [x appendString:@"<key>IOSurfacePlaneInfo</key><array><dict>"];
    [x appendFormat:@"<key>IOSurfacePlaneWidth</key><integer>%u</integer>", s->pw];
    [x appendFormat:@"<key>IOSurfacePlaneHeight</key><integer>%u</integer>", s->ph];
    [x appendFormat:@"<key>IOSurfacePlaneBytesPerElement</key><integer>%u</integer>", s->pbpe];
    [x appendFormat:@"<key>IOSurfacePlaneBytesPerRow</key><integer>%u</integer>", s->pbpr];
    [x appendFormat:@"<key>IOSurfacePlaneSize</key><integer>%u</integer>", s->psize];
    [x appendFormat:@"<key>IOSurfacePlaneCompressionType</key><integer>%u</integer>", s->comp];
    [x appendFormat:@"<key>IOSurfacePlaneDataRegionBytesPerSlice</key><integer>%u</integer>", s->dataPer];
    [x appendFormat:@"<key>IOSurfacePlaneHeaderRegionBytesPerSlice</key><integer>%u</integer>", s->headerPer];
    [x appendFormat:@"<key>IOSurfacePlaneCompressedTileWidth</key><integer>%u</integer>", s->tileW];
    [x appendFormat:@"<key>IOSurfacePlaneCompressedTileHeight</key><integer>%u</integer>", s->tileH];
    [x appendFormat:@"<key>IOSurfacePlaneBytesPerCompressedTileHeader</key><integer>%u</integer>", s->hdrBytes];
    [x appendFormat:@"<key>IOSurfacePlaneBytesPerTileData</key><integer>%u</integer>", s->tileData];
    [x appendFormat:@"<key>IOSurfacePlaneWidthInCompressedTiles</key><integer>%u</integer>", s->tilesW];
    [x appendFormat:@"<key>IOSurfacePlaneHeightInCompressedTiles</key><integer>%u</integer>", s->tilesH];
    [x appendFormat:@"<key>IOSurfacePlaneBytesPerRowOfTileData</key><integer>%u</integer>", s->tileBpr];
    [x appendFormat:@"<key>IOSurfacePlaneCompressedTileHeaderRegionOffset</key><integer>%u</integer>", s->hdrOff];
    [x appendFormat:@"<key>IOSurfacePlaneCompressedTileDataRegionOffset</key><integer>%u</integer>", s->dataOff];
    [x appendFormat:@"<key>IOSurfacePlaneBytesPerRowOfCompressedTileHeaderGroups</key><integer>%u</integer>", s->hdrGroupBpr];
    [x appendString:@"</dict></array></dict></plist>\n"];
    return x;
}

// ---------------------------------------------------------------- file dump

static void ensure_dir(void)
{
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                        NSUserDomainMask, YES);
    NSString *docs = dirs.count ? dirs[0] : NSTemporaryDirectory();
    NSString *dir = [docs stringByAppendingPathComponent:@"XMLFuzz"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:nil error:NULL];
    [[NSFileManager defaultManager] setAttributes:
        @{NSFileProtectionKey: NSFileProtectionNone}
        ofItemAtPath:dir error:NULL];
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

static NSString *dump_dir(void)
{
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                        NSUserDomainMask, YES);
    NSString *docs = dirs.count ? dirs[0] : NSTemporaryDirectory();
    return [docs stringByAppendingPathComponent:@"XMLFuzz"];
}

static void dump_last(uint64_t it, const shape_t *s, NSString *xml)
{
    ensure_dir();
    NSString *dir = dump_dir();
    NSMutableString *meta = [NSMutableString string];
    [meta appendFormat:@"iter=%llu seed=0x%llx\n", it, g_rng];
    [meta appendFormat:@"width=%u height=%u bpe=%u pixfmt=0x%x alloc=0x%x\n",
        s->width, s->height, s->bpe, s->pixfmt, s->alloc];
    [meta appendFormat:@"slices=%u pw=%u ph=%u pbpe=%u pbpr=%u psize=0x%x\n",
        s->slices, s->pw, s->ph, s->pbpe, s->pbpr, s->psize];
    [meta appendFormat:@"comp=%u dataPer=0x%x headerPer=0x%x\n",
        s->comp, s->dataPer, s->headerPer];
    [meta appendFormat:@"tileW=%u tileH=%u hdrBytes=%u tileData=0x%x\n",
        s->tileW, s->tileH, s->hdrBytes, s->tileData];
    [meta appendFormat:@"tilesW=%u tilesH=%u tileBpr=0x%x\n",
        s->tilesW, s->tilesH, s->tileBpr];
    [meta appendFormat:@"hdrOff=0x%x dataOff=0x%x hdrGroupBpr=0x%x\n",
        s->hdrOff, s->dataOff, s->hdrGroupBpr];
    write_none([dir stringByAppendingPathComponent:@"last_meta.txt"],
               [meta dataUsingEncoding:NSUTF8StringEncoding]);
    write_none([dir stringByAppendingPathComponent:@"last.xml"],
               [xml dataUsingEncoding:NSUTF8StringEncoding]);
}

// ---------------------------------------------------------------- APIs

static void probe_surface(uint32_t sid, uint64_t it)
{
    log_write(@"api: lookup sid=%u iter=%llu", sid, it);
    IOSurfaceRef s = IOSurfaceLookup(sid);
    if (!s) {
        log_write(@"api: lookup failed sid=%u", sid);
        return;
    }
    void *base = IOSurfaceGetBaseAddress(s);
    size_t alloc = IOSurfaceGetAllocSize(s);
    size_t planes = IOSurfaceGetPlaneCount(s);
    log_write(@"api: sid=%u base=%p alloc=0x%zx planes=%zu", sid, base, alloc, planes);

    log_write(@"api: lock sid=%u", sid);
    kern_return_t lk = IOSurfaceLock(s, 0, NULL);
    log_write(@"api: lock -> 0x%x", lk);
    if (lk == KERN_SUCCESS) IOSurfaceUnlock(s, 0, NULL);

    for (size_t p = 0; p < planes && p < 4; p++) {
        log_write(@"api: plane[%zu] begin", p);
        void *pb = IOSurfaceGetBaseAddressOfPlane(s, p);
        size_t bpr = IOSurfaceGetBytesPerRowOfPlane(s, p);
        size_t w = IOSurfaceGetWidthOfPlane(s, p);
        size_t h = IOSurfaceGetHeightOfPlane(s, p);
        log_write(@"api: plane[%zu] base=%p bpr=0x%zx w=%zu h=%zu",
                  p, pb, bpr, w, h);
    }
    CFRelease(s);
}

// ---------------------------------------------------------------- main loop

void fuzz_iosurface_xml(void)
{
    log_start();
    ensure_dir();
    log_write(@"fuzz: start, seed=0x%llx", g_rng);

    io_service_t svc = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                   IOServiceMatching("IOSurfaceRoot"));
    if (svc == IO_OBJECT_NULL) {
        log_write(@"fuzz: IOSurfaceRoot absent");
        ui_update(@"IOSurfaceRoot absent");
        return;
    }
    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) {
        log_write(@"fuzz: IOServiceOpen kr=0x%x", kr);
        ui_update([NSString stringWithFormat:@"IOServiceOpen kr=0x%x", kr]);
        return;
    }
    log_write(@"fuzz: IOSurfaceRoot conn=0x%x", conn);

    uint8_t out[0xc68];
    uint64_t accepted = 0;

    for (uint64_t it = 0; ; it++) {
        shape_t s;
        make_shape(&s);
        NSString *xml = xml_from_shape(&s);
        NSData *xd = [xml dataUsingEncoding:NSUTF8StringEncoding];
        if (!xd || xd.length + 1 > 0x1000) {
            continue;
        }

        NSMutableData *call = [NSMutableData dataWithData:xd];
        uint8_t nul = 0;
        [call appendBytes:&nul length:1];

        dump_last(it, &s, xml);

        uint64_t sc[1] = {0};
        size_t outSize = sizeof(out);
        memset(out, 0, sizeof(out));
        kr = IOConnectCallMethod(conn, 0, sc, 1, call.bytes, call.length,
                                 NULL, NULL, out, &outSize);
        uint32_t sid = outSize >= 0x1c ? *(uint32_t *)(out + 0x18) : 0;

        if (kr == KERN_SUCCESS) {
            accepted++;
            log_write(@"iter=%llu ACCEPT sid=%u alloc=0x%x psize=0x%x comp=%u slices=%u hdr=0x%x",
                      it, sid, s.alloc, s.psize, s.comp, s.slices, s.headerPer);
            if (sid) probe_surface(sid, it);
        } else if (it % 4096 == 0) {
            log_write(@"iter=%llu kr=0x%x accepted=%llu", it, kr, accepted);
        }

        if ((it & 0x1ff) == 0) {
            ui_update([NSString stringWithFormat:
                @"iter=%llu accepted=%llu\nlast kr=0x%x sid=%u\n"
                @"alloc=0x%x psize=0x%x\nslices=%u comp=%u\n"
                @"data=0x%x hdr=0x%x\nlog=%@",
                it, accepted, kr, sid, s.alloc, s.psize,
                s.slices, s.comp, s.dataPer, s.headerPer, log_path()]);
        }
        usleep(500);
    }
}
