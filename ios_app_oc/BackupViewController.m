#import "BackupViewController.h"
#import "ProfileManager.h"

#define CLR_BG   [UIColor colorWithRed:28/255.0  green:30/255.0  blue:42/255.0  alpha:1]
#define CLR_CARD [UIColor colorWithRed:37/255.0  green:37/255.0  blue:56/255.0  alpha:1]
#define CLR_SEL  [UIColor colorWithRed:53/255.0  green:54/255.0  blue:73/255.0  alpha:1]
#define CLR_BLUE [UIColor colorWithRed:37/255.0  green:99/255.0  blue:235/255.0 alpha:1]
#define CLR_GRN  [UIColor colorWithRed:34/255.0  green:197/255.0 blue:94/255.0  alpha:1]
#define CLR_RED  [UIColor colorWithRed:239/255.0 green:68/255.0  blue:68/255.0  alpha:1]
#define CLR_DIM  [UIColor colorWithRed:58/255.0  green:59/255.0  blue:80/255.0  alpha:1]
#define CLR_SUB  [UIColor colorWithRed:139/255.0 green:143/255.0 blue:168/255.0 alpha:1]

@interface BackupViewController () <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) UITableView         *tableView;
@property (nonatomic, strong) NSMutableArray      *backups;
@property (nonatomic, strong) NSIndexPath         *selected;
@property (nonatomic, strong) UIView              *toastView;
@end

@implementation BackupViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = CLR_BG;
    self.title = self.restoreMode ? @"选择备份还原" : @"备份管理";
    if (!self.restoreMode) {
        UIBarButtonItem *add = [[UIBarButtonItem alloc]
            initWithTitle:@"新建备份" style:UIBarButtonItemStylePlain
            target:self action:@selector(onNewBackup)];
        add.tintColor = CLR_BLUE;
        self.navigationItem.rightBarButtonItem = add;
    }
    [self buildUI];
    [self reloadBackups];
}

- (void)buildUI {
    CGFloat W = self.view.bounds.size.width;
    CGFloat H = self.view.bounds.size.height;
    CGFloat barH = 56;
    self.tableView = [[UITableView alloc] initWithFrame:CGRectMake(0, 0, W, H - barH - (self.navigationController ? 88 : 0))
        style:UITableViewStylePlain];
    self.tableView.backgroundColor = CLR_BG;
    self.tableView.separatorColor = CLR_SEL;
    self.tableView.dataSource = self;
    self.tableView.delegate   = self;
    [self.view addSubview:self.tableView];

    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, H - barH - 34, W, barH + 34)];
    bar.backgroundColor = CLR_CARD;
    [self.view addSubview:bar];

    CGFloat btnY = 8, btnH = 40;
    UIButton *closeBtn = [self makeBarButton:@"关闭" color:CLR_DIM];
    closeBtn.frame = CGRectMake(12, btnY, 80, btnH);
    [closeBtn addTarget:self action:@selector(onClose) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:closeBtn];

    if (!self.restoreMode) {
        UIButton *del = [self makeBarButton:@"删除" color:CLR_RED];
        del.frame = CGRectMake(W - 12 - 80 - 8 - 80, btnY, 80, btnH);
        [del addTarget:self action:@selector(onDelete) forControlEvents:UIControlEventTouchUpInside];
        [bar addSubview:del];
    }

    CGFloat restoreX = W - 12 - 80;
    UIButton *restore = [self makeBarButton:@"还原" color:CLR_GRN];
    restore.frame = CGRectMake(restoreX, btnY, 80, btnH);
    [restore addTarget:self action:@selector(onRestore) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:restore];
}

- (UIButton *)makeBarButton:(NSString *)title color:(UIColor *)color {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.backgroundColor = color;
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:14];
    b.layer.cornerRadius = 10;
    return b;
}

- (void)reloadBackups {
    self.backups = [[[ProfileManager shared] listBackups] mutableCopy];
    [self.tableView reloadData];
    self.selected = nil;
}

// ── TableView ──────────────────────────────────────────────────────────────
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)sec {
    return self.backups.count;
}

- (CGFloat)tableView:(UITableView *)tv heightForRowAtIndexPath:(NSIndexPath *)ip {
    return 68;
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:@"C"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"C"];
        cell.backgroundColor = CLR_BG;
        cell.textLabel.textColor = [UIColor whiteColor];
        cell.textLabel.font = [UIFont systemFontOfSize:14];
        cell.detailTextLabel.textColor = CLR_SUB;
        cell.detailTextLabel.font = [UIFont systemFontOfSize:12];
        cell.detailTextLabel.numberOfLines = 2;
        cell.selectedBackgroundView = [[UIView alloc] init];
        cell.selectedBackgroundView.backgroundColor = CLR_SEL;
    }
    NSDictionary *b = self.backups[ip.row];
    cell.textLabel.text = b[@"name"];
    NSDate *date = b[@"date"];
    NSString *ds = [NSDateFormatter localizedStringFromDate:date dateStyle:NSDateFormatterShortStyle timeStyle:NSDateFormatterShortStyle];
    NSInteger sz = [b[@"size"] integerValue];
    cell.detailTextLabel.text = [NSString stringWithFormat:@"IDFV: %@\n%@  %ldB", b[@"idfv"], ds, (long)sz];
    cell.backgroundColor = [self.selected isEqual:ip] ? CLR_SEL : CLR_BG;
    return cell;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    self.selected = ip;
    [tv reloadData];
}

// ── Actions ───────────────────────────────────────────────────────────────
- (void)onNewBackup {
    NSError *e;
    BOOL ok = [[ProfileManager shared] backupWithError:&e];
    [self showToast:ok ? @"备份成功" : (e.localizedDescription ?: @"备份失败")
              color:ok ? CLR_GRN : CLR_RED];
    if (ok) [self reloadBackups];
}

- (void)onRestore {
    if (!self.selected) { [self showToast:@"请先选择备份" color:CLR_RED]; return; }
    NSDictionary *b = self.backups[self.selected.row];
    NSError *e;
    BOOL ok = [[ProfileManager shared] restoreFromPath:b[@"path"] error:&e];
    [self showToast:ok ? @"还原成功" : (e.localizedDescription ?: @"还原失败")
              color:ok ? CLR_GRN : CLR_RED];
}

- (void)onDelete {
    if (!self.selected) { [self showToast:@"请先选择备份" color:CLR_RED]; return; }
    NSDictionary *b = self.backups[self.selected.row];
    NSError *e;
    [[NSFileManager defaultManager] removeItemAtPath:b[@"path"] error:&e];
    [self showToast:e ? (e.localizedDescription ?: @"删除失败") : @"已删除"
              color:e ? CLR_RED : CLR_GRN];
    if (!e) [self reloadBackups];
}

- (void)onClose { [self.navigationController popViewControllerAnimated:YES]; }

// ── Toast ──────────────────────────────────────────────────────────────────
- (void)showToast:(NSString *)msg color:(UIColor *)color {
    [self.toastView removeFromSuperview];
    UIView *t = [[UIView alloc] initWithFrame:CGRectMake(20, self.view.bounds.size.height - 200,
        self.view.bounds.size.width - 40, 44)];
    t.backgroundColor = color; t.layer.cornerRadius = 10; t.alpha = 0;
    UILabel *l = [[UILabel alloc] initWithFrame:CGRectInset(t.bounds, 10, 4)];
    l.text = msg; l.textColor = [UIColor whiteColor];
    l.font = [UIFont systemFontOfSize:13]; l.textAlignment = NSTextAlignmentCenter;
    [t addSubview:l]; [self.view addSubview:t];
    self.toastView = t;
    [UIView animateWithDuration:0.3 animations:^{ t.alpha = 1; } completion:^(BOOL _) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            [UIView animateWithDuration:0.3 animations:^{ t.alpha = 0; }
                completion:^(BOOL __) { [t removeFromSuperview]; }];
        });
    }];
}

@end
