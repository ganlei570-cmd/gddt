#import "BackupViewController.h"
#import "ProfileManager.h"

#define CLR_BLUE [UIColor colorWithRed:37/255.0  green:99/255.0  blue:235/255.0 alpha:1]
#define CLR_GRN  [UIColor colorWithRed:34/255.0  green:197/255.0 blue:94/255.0  alpha:1]
#define CLR_RED  [UIColor colorWithRed:239/255.0 green:68/255.0  blue:68/255.0  alpha:1]
#define CLR_SUB  [UIColor colorWithRed:120/255.0 green:120/255.0 blue:128/255.0 alpha:1]
#define CLR_SEP  [UIColor colorWithRed:210/255.0 green:210/255.0 blue:215/255.0 alpha:1]
#define CLR_SEL  [UIColor colorWithRed:219/255.0 green:234/255.0 blue:254/255.0 alpha:1]

@interface BackupViewController () <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) UITableView     *tableView;
@property (nonatomic, strong) NSMutableArray  *backups;
@property (nonatomic, strong) UIBarButtonItem *deleteNavBtn;
@property (nonatomic, strong) UIView          *toastView;
@property (nonatomic, assign) BOOL            isEditing;
@end

@implementation BackupViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor whiteColor];
    self.title = self.restoreMode ? @"选择备份还原" : @"备份管理";
    self.tableView = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStylePlain];
    self.tableView.backgroundColor = [UIColor whiteColor];
    self.tableView.separatorColor  = CLR_SEP;
    self.tableView.allowsMultipleSelectionDuringEditing = YES;
    self.tableView.dataSource = self;
    self.tableView.delegate   = self;
    self.tableView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:self.tableView];
    if (!self.restoreMode) [self setupNormalNav];
    [self reloadBackups];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
}

- (void)setupNormalNav {
    self.navigationItem.leftBarButtonItem  = nil;
    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc]
        initWithTitle:@"编辑" style:UIBarButtonItemStylePlain
        target:self action:@selector(onToggleEdit)];
}

- (void)reloadBackups {
    self.backups = [[[ProfileManager shared] listBackups] mutableCopy];
    [self.tableView reloadData];
}

// ── TableView ─────────────────────────────────────────────────────────────
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return self.backups.count; }
- (CGFloat)tableView:(UITableView *)tv heightForRowAtIndexPath:(NSIndexPath *)ip { return 64; }

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *cell = [tv dequeueReusableCellWithIdentifier:@"C"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"C"];
        cell.backgroundColor = [UIColor whiteColor];
        cell.textLabel.font  = [UIFont boldSystemFontOfSize:15];
        cell.detailTextLabel.textColor = CLR_SUB;
        cell.detailTextLabel.font = [UIFont systemFontOfSize:12];
        UIView *selBg = [[UIView alloc] init];
        selBg.backgroundColor = CLR_SEL;
        cell.selectedBackgroundView = selBg;
    }
    NSDictionary *b = self.backups[ip.row];
    BOOL active = [b[@"active"] boolValue];
    cell.textLabel.text      = active ? [NSString stringWithFormat:@"✓ %@", b[@"name"]] : b[@"name"];
    cell.textLabel.textColor = active ? CLR_GRN : [UIColor blackColor];
    cell.detailTextLabel.text = [NSString stringWithFormat:@"%@  %@  %@ MB",
        b[@"model"], b[@"date"], b[@"size_mb"]];
    return cell;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    if (self.isEditing) { [self syncDeleteTitle]; return; }
    [tv deselectRowAtIndexPath:ip animated:YES];
    NSDictionary *b = self.backups[ip.row];
    NSString *msg = [NSString stringWithFormat:@"%@\n%@  %@ MB",
        b[@"name"], b[@"date"], b[@"size_mb"]];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"切换备份"
        message:msg preferredStyle:UIAlertControllerStyleAlert];
    alert.overrideUserInterfaceStyle = UIUserInterfaceStyleLight;
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"进入此备份" style:UIAlertActionStyleDefault
        handler:^(UIAlertAction *_) {
            NSError *e;
            BOOL ok = [[ProfileManager shared] restoreFromPath:b[@"path"] error:&e];
            if (ok) {
                [ProfileManager shared].activeBackupName = b[@"name"];
                [b[@"name"] writeToFile:@"/var/mobile/Documents/amap_backups/active_backup"
                    atomically:YES encoding:NSUTF8StringEncoding error:nil];
                [self reloadBackups];
            }
            [self showToast:ok ? @"已切换，请重启高德地图" : (e.localizedDescription ?: @"切换失败")
                      color:ok ? CLR_GRN : CLR_RED];
        }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)tableView:(UITableView *)tv didDeselectRowAtIndexPath:(NSIndexPath *)ip {
    if (self.isEditing) [self syncDeleteTitle];
}

// ── 编辑模式 ──────────────────────────────────────────────────────────────
- (void)onToggleEdit {
    self.isEditing = !self.isEditing;
    [self.tableView setEditing:self.isEditing animated:YES];
    if (!self.isEditing) { [self setupNormalNav]; return; }

    UIBarButtonItem *done = [[UIBarButtonItem alloc]
        initWithTitle:@"完成" style:UIBarButtonItemStyleDone
        target:self action:@selector(onToggleEdit)];
    self.deleteNavBtn = [[UIBarButtonItem alloc]
        initWithTitle:@"删除" style:UIBarButtonItemStylePlain
        target:self action:@selector(onDelete)];
    self.deleteNavBtn.tintColor = CLR_RED;
    self.navigationItem.rightBarButtonItems = @[done, self.deleteNavBtn];

    UIBarButtonItem *selAll = [[UIBarButtonItem alloc]
        initWithTitle:@"全选" style:UIBarButtonItemStylePlain
        target:self action:@selector(onSelectAll)];
    selAll.tintColor = CLR_BLUE;
    self.navigationItem.leftBarButtonItem = selAll;
}

- (void)syncDeleteTitle {
    NSUInteger n = self.tableView.indexPathsForSelectedRows.count;
    self.deleteNavBtn.title = n > 0
        ? [NSString stringWithFormat:@"删除(%lu)", (unsigned long)n] : @"删除";
    BOOL allSel = n == (NSUInteger)[self.tableView numberOfRowsInSection:0];
    self.navigationItem.leftBarButtonItem.title = allSel ? @"取消全选" : @"全选";
}

- (void)onSelectAll {
    NSInteger total = [self.tableView numberOfRowsInSection:0];
    BOOL allSel = (NSInteger)self.tableView.indexPathsForSelectedRows.count == total;
    for (NSInteger i = 0; i < total; i++) {
        NSIndexPath *ip = [NSIndexPath indexPathForRow:i inSection:0];
        if (allSel) [self.tableView deselectRowAtIndexPath:ip animated:NO];
        else [self.tableView selectRowAtIndexPath:ip animated:NO
            scrollPosition:UITableViewScrollPositionNone];
    }
    [self syncDeleteTitle];
}

- (void)onDelete {
    NSArray *selected = self.tableView.indexPathsForSelectedRows;
    if (!selected.count) { [self showToast:@"请先选择要删除的备份" color:CLR_RED]; return; }
    NSUInteger cnt = selected.count;
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"确认删除"
        message:[NSString stringWithFormat:@"将删除 %lu 个备份，不可恢复", (unsigned long)cnt]
        preferredStyle:UIAlertControllerStyleAlert];
    alert.overrideUserInterfaceStyle = UIUserInterfaceStyleLight;
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:@"删除" style:UIAlertActionStyleDestructive
        handler:^(UIAlertAction *_) {
            NSArray *desc = [selected sortedArrayUsingComparator:^(NSIndexPath *a, NSIndexPath *b) {
                return a.row < b.row ? NSOrderedDescending : NSOrderedAscending;
            }];
            for (NSIndexPath *ip in desc) {
                [[ProfileManager shared] deleteBackupAtPath:self.backups[ip.row][@"path"] error:nil];
                [self.backups removeObjectAtIndex:ip.row];
            }
            [self.tableView reloadData];
            [self showToast:[NSString stringWithFormat:@"已删除 %lu 个备份", (unsigned long)cnt]
                      color:CLR_GRN];
            [self onToggleEdit];
        }]];
    [self presentViewController:alert animated:YES completion:nil];
}

// ── Toast ──────────────────────────────────────────────────────────────────
- (void)showToast:(NSString *)msg color:(UIColor *)color {
    [self.toastView removeFromSuperview];
    UIView *t = [[UIView alloc] initWithFrame:CGRectMake(20,
        self.view.bounds.size.height - 120, self.view.bounds.size.width - 40, 44)];
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
