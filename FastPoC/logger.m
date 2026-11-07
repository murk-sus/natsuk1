#import "logger.h"
#import <execinfo.h>
#import <signal.h>
#import <unistd.h>
#import <fcntl.h>
#import <string.h>
#import <sys/utsname.h>

static int g_fd = -1;
static NSString *g_path = nil;
static NSString *g_folder = nil;

static void set_none(NSString *path)
{
    [[NSFileManager defaultManager] setAttributes:
        @{NSFileProtectionKey: NSFileProtectionNone}
        ofItemAtPath:path error:NULL];
}

static void crash_handler(int sig)
{
    if (g_fd >= 0) {
        char buf[128];
        int n = snprintf(buf, sizeof(buf), "\n=== SIGNAL %d (%s) ===\n", sig, strsignal(sig));
        if (n > 0) write(g_fd, buf, (size_t)n);
        void *bt[64];
        int frames = backtrace(bt, 64);
        backtrace_symbols_fd(bt, frames, g_fd);
        fsync(g_fd);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

NSString *log_path(void) { return g_path; }

NSString *log_start(void)
{
    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                        NSUserDomainMask, YES);
    NSString *docs = dirs.count ? dirs[0] : NSTemporaryDirectory();
    g_folder = [docs stringByAppendingPathComponent:@"AGXReconnect"];
    [[NSFileManager defaultManager] createDirectoryAtPath:g_folder
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:NULL];
    set_none(g_folder);

    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"yyyyMMdd-HHmmss";
    g_path = [g_folder stringByAppendingPathComponent:
              [NSString stringWithFormat:@"fuzz-%@.log",
               [fmt stringFromDate:[NSDate date]]]];
    g_fd = open(g_path.fileSystemRepresentation, O_CREAT | O_WRONLY | O_APPEND, 0644);
    set_none(g_path);

    signal(SIGSEGV, crash_handler);
    signal(SIGBUS, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGILL, crash_handler);
    signal(SIGFPE, crash_handler);
    signal(SIGTRAP, crash_handler);

    log_write(@"=== IOSurface XML fuzz start ===");
    struct utsname u = {0};
    if (uname(&u) == 0) {
        log_write(@"sysname=%s release=%s version=%s", u.sysname, u.release, u.version);
    }
    log_write(@"log path: %@", g_path);
    return g_path;
}

void log_write(NSString *fmt, ...)
{
    if (g_fd < 0) return;
    va_list ap;
    va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSDateFormatter *fmt2 = [[NSDateFormatter alloc] init];
    fmt2.dateFormat = @"HH:mm:ss.SSS";
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n",
                      [fmt2 stringFromDate:[NSDate date]], msg];
    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
    if (data) {
        write(g_fd, data.bytes, data.length);
        fsync(g_fd);
    }
    NSLog(@"[AGXRC] %@", msg);
}

void log_flush(void)
{
    if (g_fd >= 0) fsync(g_fd);
}
