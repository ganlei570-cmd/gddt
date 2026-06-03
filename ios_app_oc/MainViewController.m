#import "MainViewController.h"
#import "BackupViewController.h"
#import "ProfileManager.h"
#import "Logger.h"

#define CLR_BG   [UIColor whiteColor]
#define CLR_CARD [UIColor colorWithRed:245/255.0 green:245/255.0 blue:247/255.0 alpha:1]
#define CLR_BTN  [UIColor colorWithRed:37/255.0  green:99/255.0  blue:235/255.0 alpha:1]
#define CLR_GRN  [UIColor colorWithRed:34/255.0  green:197/255.0 blue:94/255.0  alpha:1]
#define CLR_RED  [UIColor colorWithRed:239/255.0 green:68/255.0  blue:68/255.0  alpha:1]
#define CLR_SUB  [UIColor colorWithRed:120/255.0 green:120/255.0 blue:128/255.0 alpha:1]

static NSArray<NSString *> *btnTitles(void) {
    return @[@"一键新机", @"清理Safari", @"备份记录", @"清理剪贴板", @"清理Keychain", @"还原机器"];
}

@interface MainViewController ()
@property (nonatomic, strong) UIScrollView *scroll;
@property (nonatomic, strong) UILabel      *idfvLabel;
@property (nonatomic, strong) UILabel      *modelLabel;
@property (nonatomic, strong) UILabel      *sysLabel;
@property (nonatomic, strong) UIView       *toastView;
@end

@implementation MainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [Logger log:@"app_open"];
    self.title = @"一键新机";
    self.view.backgroundColor = CLR_BG;
    self.navigationItem.hidesBackButton = YES;
    UIBarButtonItem *logout = [[UIBarButtonItem alloc]
        initWithTitle:@"安全退出" style:UIBarButtonItemStylePlain
        target:self action:@selector(onLogout)];
    logout.tintColor = CLR_RED;
    self.navigationItem.rightBarButtonItem = logout;
    [self buildUI];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self refreshCard];
}

- (void)buildUI {
    CGFloat W = self.view.bounds.size.width;
    self.scroll = [[UIScrollView alloc] initWithFrame:self.view.bounds];
    self.scroll.alwaysBounceVertical = YES;
    [self.view addSubview:self.scroll];

    // 设备信息卡片
    UIView *card = [[UIView alloc] initWithFrame:CGRectMake(16, 16, W - 32, 90)];
    card.backgroundColor = CLR_CARD;
    card.layer.cornerRadius = 12;
    [self.scroll addSubview:card];

    UILabel *icon = [UILabel new];
    icon.text = @"📱";
    icon.font = [UIFont systemFontOfSize:30];
    icon.frame = CGRectMake(16, 20, 50, 50);
    [card addSubview:icon];

    self.modelLabel = [self infoLabelIn:card frame:CGRectMake(72, 12, card.bounds.size.width - 88, 22) size:15 bold:YES];
    self.sysLabel   = [self infoLabelIn:card frame:CGRectMake(72, 36, card.bounds.size.width - 88, 18) size:13 bold:NO];
    self.sysLabel.textColor = CLR_SUB;
    self.idfvLabel  = [self infoLabelIn:card frame:CGRectMake(72, 56, card.bounds.size.width - 88, 18) size:12 bold:NO];
    self.idfvLabel.textColor = CLR_SUB;

    // 按钮网格
    CGFloat gap = 10, btnW = (W - 32 - gap) / 2, btnH = 44;
    NSArray *titles = btnTitles();
    for (NSInteger i = 0; i < titles.count; i++) {
        CGFloat x = 16 + (i % 2) * (btnW + gap);
        CGFloat y = 122 + (i / 2) * (btnH + gap);
        UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
        btn.frame = CGRectMake(x, y, btnW, btnH);
        btn.backgroundColor = CLR_BTN;
        [btn setTitle:titles[i] forState:UIControlStateNormal];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        btn.titleLabel.font = [UIFont systemFontOfSize:13];
        btn.layer.cornerRadius = 10;
        btn.tag = i;
        [btn addTarget:self action:@selector(onButton:) forControlEvents:UIControlEventTouchUpInside];
        [self.scroll addSubview:btn];
    }
    CGFloat contentH = 122 + 3 * (btnH + gap) + 20;
    self.scroll.contentSize = CGSizeMake(W, contentH);
}

- (UILabel *)infoLabelIn:(UIView *)parent frame:(CGRect)f size:(CGFloat)sz bold:(BOOL)bold {
    UILabel *l = [[UILabel alloc] initWithFrame:f];
    l.font = bold ? [UIFont boldSystemFontOfSize:sz] : [UIFont systemFontOfSize:sz];
    l.textColor = [UIColor blackColor];
    [parent addSubview:l];
    return l;
}

- (void)refreshCard {
    UIDevice *dev = [UIDevice currentDevice];
    self.modelLabel.text = dev.name ?: @"iPhone";
    self.sysLabel.text   = [NSString stringWithFormat:@"iOS %@", dev.systemVersion];
    NSString *idfv = [ProfileManager shared].activeIdfv ?: @"";
    NSString *prefix = idfv.length >= 8 ? [idfv substringToIndex:8] : idfv;
    self.idfvLabel.text = [NSString stringWithFormat:@"IDFV: %@...", prefix];
}

- (void)onButton:(UIButton *)btn {
    switch (btn.tag) {
        case 0: [self doNewMachine]; break;
        case 1: [self doClearSafari]; break;
        case 2: [self doBackup]; break;
        case 3: [self doClearClipboard]; break;
        case 4: [self doClearKeychain]; break;
        case 5: [self doRestore]; break;
    }
}

- (NSInteger)clearSafariData {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *base = @"/var/mobile/Library/Safari";
    NSArray *targets = @[
        @"History.db", @"History.db-shm", @"History.db-wal",
        @"BrowserState.db", @"BrowserState.db-shm", @"BrowserState.db-wal",
        @"SafariTabs.db", @"SafariTabs.db-shm", @"SafariTabs.db-wal",
        @"CloudTabs.db", @"CloudTabs.db-shm", @"CloudTabs.db-wal",
    ];
    NSInteger n = 0;
    for (NSString *f in targets) {
        NSString *p = [base stringByAppendingPathComponent:f];
        if ([fm fileExistsAtPath:p] && [fm removeItemAtPath:p error:nil]) n++;
    }
    return n;
}

- (void)doNewMachine {
    UIAlertController *hud = [UIAlertController
        alertControllerWithTitle:@"一键新机" message:@"正在备份高德数据..."
        preferredStyle:UIAlertControllerStyleAlert];
    hud.overrideUserInterfaceStyle = UIUserInterfaceStyleLight;
    [self presentViewController:hud animated:YES completion:nil];

    [[ProfileManager shared] newMachineAsync:^(BOOL done, NSString *status, NSError *err) {
        if (!done) { hud.message = status; return; }
        [hud dismissViewControllerAnimated:YES completion:^{
            if (!err) {
                [self clearSafariData];
                NSString *idfv = [ProfileManager shared].activeIdfv ?: @"";
                NSString *pre  = idfv.length >= 8 ? [idfv substringToIndex:8] : idfv;
                [Logger log:@"new_machine_ok" info:@{@"idfv_prefix": pre}];
                [self showToast:[NSString stringWithFormat:@"新机完成\nIDFV:%@\n数据已清理并备份\n请重启高德地图", pre]
                          color:CLR_GRN];
                [self refreshCard];
            } else {
                NSString *msg = err.localizedDescription ?: @"操作失败";
                [Logger log:@"new_machine_fail" info:@{@"err": msg}];
                [self showToast:msg color:CLR_RED];
            }
        }];
    }];
}

- (void)doClearSafari {
    NSInteger n = [self clearSafariData];
    [Logger log:@"clear_safari" info:@{@"count": @(n)}];
    [self showToast:n > 0
        ? [NSString stringWithFormat:@"Safari 已清理（%ld项）", (long)n]
        : @"Safari 无数据"
        color:CLR_GRN];
}

- (void)doBackup {
    BackupViewController *vc = [BackupViewController new];
    vc.restoreMode = NO;
    [self.navigationController pushViewController:vc animated:YES];
}

- (void)doClearClipboard {
    [UIPasteboard generalPasteboard].items = @[];
    [self showToast:@"剪贴板已清理" color:CLR_GRN];
}

- (void)doClearKeychain {
    NSError *e;
    BOOL ok = [[ProfileManager shared] clearKeychainWithError:&e];
    [Logger log:ok ? @"clear_keychain_ok" : @"clear_keychain_fail"
           info:ok ? nil : @{@"err": e.localizedDescription ?: @"未知"}];
    [self showToast:ok ? @"Keychain 标记已清理" : (e.localizedDescription ?: @"失败")
              color:ok ? CLR_GRN : CLR_RED];
}

- (void)doRestore {
    BackupViewController *vc = [BackupViewController new];
    vc.restoreMode = YES;
    [self.navigationController pushViewController:vc animated:YES];
}

- (void)onLogout {
    [self.navigationController popToRootViewControllerAnimated:YES];
}

// ── Toast ──────────────────────────────────────────────────────────────────
- (void)showToast:(NSString *)msg color:(UIColor *)color {
    [self.toastView removeFromSuperview];
    UIView *toast = [[UIView alloc] initWithFrame:CGRectMake(20,
        self.view.bounds.size.height - 120, self.view.bounds.size.width - 40, 60)];
    toast.backgroundColor = color;
    toast.layer.cornerRadius = 12;
    toast.alpha = 0;
    UILabel *l = [[UILabel alloc] initWithFrame:CGRectInset(toast.bounds, 12, 6)];
    l.text = msg; l.textColor = [UIColor whiteColor];
    l.font = [UIFont systemFontOfSize:13]; l.numberOfLines = 3;
    l.textAlignment = NSTextAlignmentCenter;
    [toast addSubview:l];
    [self.view addSubview:toast];
    self.toastView = toast;
    [UIView animateWithDuration:0.3 animations:^{ toast.alpha = 1; } completion:^(BOOL f) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
            dispatch_get_main_queue(), ^{
            [UIView animateWithDuration:0.3 animations:^{ toast.alpha = 0; }
                completion:^(BOOL _) { [toast removeFromSuperview]; }];
        });
    }];
}

@end
