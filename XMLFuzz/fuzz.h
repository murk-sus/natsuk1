#import <Foundation/Foundation.h>

// Runs the IOSurface compressed-plane XML fuzzer.  Never returns unless the
// kernel panics or the process is killed.
void fuzz_iosurface_xml(void);

// Implemented in main.m: updates the on-screen log.
void ui_update(NSString *text);
