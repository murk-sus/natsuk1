#import <Foundation/Foundation.h>

NSString *log_start(void);
void log_write(NSString *fmt, ...);
void log_flush(void);
NSString *log_path(void);
