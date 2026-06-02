#import "LoginViewController.h"
#import "MainViewController.h"
#import "XBZhanAuth.h"

#define CLR_BG   [UIColor colorWithRed:28/255.0  green:30/255.0  blue:42/255.0  alpha:1]
#define CLR_CARD [UIColor colorWithRed:37/255.0  green:37/255.0  blue:56/255.0  alpha:1]
#define CLR_BLUE [UIColor colorWithRed:37/255.0  green:99/255.0  blue:235/255.0 alpha:1]
#define CLR_SUB  [UIColor colorWithRed:139/255.0 green:143/255.0 blue:168/255.0 alpha:1]
#define CLR_RED  [UIColor colorWithRed:239/255.0 green:68/255.0  blue:68/255.0  alpha:1]
#define CLR_GRN  [UIColor colorWithRed:34/255.0  green:197/255.0 blue:94/255.0  alpha:1]

@interface LoginViewController ()
@property (nonatomic, strong) UITextField  *keyField;
@property (nonatomic, strong) UILabel      *statusLabel;
@property (nonatomic, strong) UIButton     *loginBtn;
@property (nonatomic, assign) BOOL         autoLoginDone;
@end

@implementation LoginViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"";
    self.navigationItem.hidesBackButton = YES;
    self.view.backgroundColor = CLR_BG;
    [self buildUI];
    NSString *cached = [[XBZhanAuth shared] loadCachedKey];
    if (cached.length) self.keyField.text = cached;
    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc]
        initWithTarget:self action:@selector(dismissKeyboard)];
    [self.view addGestureRecognizer:tap];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    if (self.autoLoginDone) return;
    NSString *cached = [[XBZhanAuth shared] loadCachedKey];
    if (cached.length) {
        self.autoLoginDone = YES;
        [self doLoginWithKey:cached];
    }
}

- (void)buildUI {
    CGFloat W = self.view.bounds.size.width;
    UILabel *title = [UILabel new];
    title.text = @"一键新机";
    title.font = [UIFont boldSystemFontOfSize:28];
    title.textColor = [UIColor whiteColor];
    title.textAlignment = NSTextAlignmentCenter;
    title.frame = CGRectMake(20, 100, W - 40, 40);
    [self.view addSubview:title];

    UILabel *sub = [UILabel new];
    sub.text = @"输入卡密以继续";
    sub.font = [UIFont systemFontOfSize:13];
    sub.textColor = CLR_SUB;
    sub.textAlignment = NSTextAlignmentCenter;
    sub.frame = CGRectMake(20, 148, W - 40, 20);
    [self.view addSubview:sub];

    self.keyField = [[UITextField alloc] initWithFrame:CGRectMake(24, 196, W - 48, 50)];
    self.keyField.backgroundColor = CLR_CARD;
    self.keyField.textColor = [UIColor whiteColor];
    self.keyField.font = [UIFont systemFontOfSize:15];
    self.keyField.layer.cornerRadius = 10;
    self.keyField.layer.masksToBounds = YES;
    self.keyField.leftView = [[UIView alloc] initWithFrame:CGRectMake(0,0,14,1)];
    self.keyField.leftViewMode = UITextFieldViewModeAlways;
    self.keyField.returnKeyType = UIReturnKeyDone;
    NSAttributedString *ph = [[NSAttributedString alloc] initWithString:@"请输入卡密"
        attributes:@{NSForegroundColorAttributeName: CLR_SUB}];
    self.keyField.attributedPlaceholder = ph;
    [self.view addSubview:self.keyField];

    self.statusLabel = [UILabel new];
    self.statusLabel.font = [UIFont systemFontOfSize:13];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    self.statusLabel.numberOfLines = 2;
    self.statusLabel.frame = CGRectMake(24, 254, W - 48, 36);
    [self.view addSubview:self.statusLabel];

    self.loginBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.loginBtn.frame = CGRectMake(24, 298, W - 48, 50);
    self.loginBtn.backgroundColor = CLR_BLUE;
    [self.loginBtn setTitle:@"登 录" forState:UIControlStateNormal];
    [self.loginBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.loginBtn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    self.loginBtn.layer.cornerRadius = 12;
    self.loginBtn.layer.masksToBounds = YES;
    [self.loginBtn addTarget:self action:@selector(onLogin) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.loginBtn];

    UIButton *unbind = [UIButton buttonWithType:UIButtonTypeSystem];
    unbind.frame = CGRectMake(24, 362, W - 48, 30);
    [unbind setTitle:@"解绑当前设备" forState:UIControlStateNormal];
    [unbind setTitleColor:CLR_SUB forState:UIControlStateNormal];
    unbind.titleLabel.font = [UIFont systemFontOfSize:13];
    [unbind addTarget:self action:@selector(onUnbind) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:unbind];
}

- (void)onLogin {
    [self doLoginWithKey:self.keyField.text];
}

- (void)doLoginWithKey:(NSString *)key {
    if (!key.length) { [self showStatus:@"请输入卡密" ok:NO]; return; }
    self.loginBtn.enabled = NO;
    [self showStatus:@"验证中..." ok:YES];
    [[XBZhanAuth shared] loginWithKey:key completion:^(BOOL ok, NSString *msg) {
        self.loginBtn.enabled = YES;
        [self showStatus:msg ok:ok];
        if (ok) {
            [self.navigationController pushViewController:[MainViewController new] animated:YES];
        }
    }];
}

- (void)onUnbind {
    NSString *key = self.keyField.text;
    if (!key.length) { [self showStatus:@"请先输入卡密" ok:NO]; return; }
    [[XBZhanAuth shared] unbindAllWithKey:key completion:^(BOOL ok, NSString *msg) {
        [self showStatus:msg ok:ok];
    }];
}

- (void)showStatus:(NSString *)msg ok:(BOOL)ok {
    self.statusLabel.text = msg;
    self.statusLabel.textColor = ok ? CLR_GRN : CLR_RED;
}

- (void)dismissKeyboard { [self.view endEditing:YES]; }

@end
