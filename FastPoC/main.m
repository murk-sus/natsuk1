#import <UIKit/UIKit.h>
#import "poc.h"

static UITextView *g_view = nil;

void ui_update(NSString *text)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_view) {
            g_view.text = text;
            [g_view setContentOffset:CGPointZero animated:NO];
        }
    });
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic, strong) UITextView *tv;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app
    didFinishLaunchingWithOptions:(NSDictionary *)opts
{
    [UIApplication sharedApplication].idleTimerDisabled = YES;
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];
    self.tv = [[UITextView alloc] initWithFrame:vc.view.bounds];
    self.tv.editable = NO;
    self.tv.selectable = NO;
    self.tv.backgroundColor = [UIColor blackColor];
    self.tv.textColor = [UIColor greenColor];
    self.tv.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.tv.text = @"AGXReconnect starting...";
    [vc.view addSubview:self.tv];
    g_view = self.tv;
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            @autoreleasepool { poc_run(); }
        });
    });
    return YES;
}
@end

int main(int argc, char **argv)
{
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
