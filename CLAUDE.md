# IOS-GDDT 项目规则

## 项目概览
- **项目名**: IOS-GDDT — 高德地图 iOS 16.02.1 一键新机插件
- **平台**: iOS（越狱 Dopamine）
- **目标 App**: 高德地图 `com.autonavi.amap` / 进程名 `AMapiPhone`
- **开发语言**: JavaScript（Frida 脚本）、Python（备份/还原工具）、Objective-C（Theos Tweak）

## 侦察结论（已完成）
| 项目 | 结论 |
|------|------|
| 壳 | 仅标准 FairPlay DRM，**无商业加固壳** |
| 安全 SDK | `DTHbalSe.framework`（Alibaba 风控 SDK，名称混淆，2.7MB）|
| Frida 检测 | **强**：attach 超时 + spawn 后连接主动关闭 |
| 主二进制 | 137MB，全量 SDK 编译进主体 |
| 越狱环境 | Dopamine（已从 systemhook.dylib 路径确认）|
| DTHbalSe imports | `sysctlbyname`（系统调用检测）|
| DTHbalSe exports | MNN 神经网络推理框架（AI 风控模型）|

## 设备 & 连接信息
```
设备 IP          : 192.168.31.164
Frida 设备 ID    : fcb0b05ae20229767149e98cb3ac94dcde52f74f
PC Frida 版本    : 16.7.19（已与手机匹配）
App Bundle 路径  : /private/var/containers/Bundle/Application/
                   31E9B1BB-712B-417D-994A-7C4E451BB15F/AMapiPhone.app/
```

## 目标交付设备范围
| 机型 | 芯片 | iOS | 越狱 |
|------|------|-----|------|
| iPhone 11 Pro Max | A13 (arm64e) | 15-16 | Dopamine |
| iPhone 12 系列 | A14 (arm64e) | 15-16 | Dopamine |

**关键约束**：
- 架构：`arm64e`（iPhone 11 及以后，需同时打包 arm64 + arm64e）
- 注入框架：**ElleKit**（Dopamine 用 ElleKit，不是 Substrate/CydiaSubstrate）
- iOS 范围：15.0 ~ 16.6.1（Dopamine 支持范围）
- Tweak 依赖：`org.coolstar.ellekit`，**不依赖** `mobilesubstrate`

## 目录结构
```
IOS-GDDT/
├── CLAUDE.md
├── Reverse/
│   ├── output/          ← 逆向产出（Frida脚本、Python工具）
│   │   ├── scripts/
│   │   │   ├── frida/
│   │   │   │   ├── bypass.js    ← 阶段一：绕过DTHbalSe检测
│   │   │   │   ├── spoof.js     ← 阶段二：设备指纹伪装
│   │   │   │   └── debug/       ← 一次性探测脚本（用完删）
│   │   │   └── python/
│   │   │       ├── backup.py    ← 阶段三：备份设备信息+登录态
│   │   │       └── restore.py   ← 阶段三：还原
│   │   ├── profiles/            ← 设备 profile JSON 存档
│   │   └── tweak/               ← 阶段四：Theos Tweak 源码
│   ├── samples/         ← 抓包样本、原始文件
│   └── notes/
│       └── 分析报告.md  ← 每阶段完成后更新
└── files/               ← 安装包等（iTunes、爱思助手）
```

## 逆向目标清单（按依赖顺序）

### RT-1｜DTHbalSe 检测绕过（阻塞项，必须最先完成）
**目标**：找到并 Hook 以下检测点，让 Frida attach 后稳定运行
| 检测点 | 手段 | 状态 |
|--------|------|------|
| Frida 端口探测（27042） | Hook `connect` / `sysctlbyname` | ✅ |
| `/proc/self/maps` 扫描 | Hook 文件读取路径过滤 | ✅ |
| 越狱文件路径检测 | Hook `access` / `stat` / `fopen` | ✅ |
| dylib 注入检测 | Hook `dlopen` / `_dyld_image_count` | ✅ |
| 反调试 `ptrace` | Hook `ptrace` 返回 0 | ✅ |
| `task_info` 调试检测 | Hook 返回非调试状态 | ✅ |

**产出**：`bypass.js` — 所有检测点全部绕过后才算完成

---

### RT-2｜设备指纹采集点定位（依赖 RT-1）
**目标**：动态 Hook 打印高德读取的所有设备标识符及调用栈
| 采集点 | Hook 方法 | 关注内容 |
|--------|-----------|---------|
| IDFV | `[UIDevice identifierForVendor]` | 返回值 UUID |
| IDFA | `ASIdentifierManager.advertisingIdentifier` | 返回值 UUID |
| 设备名/型号 | `[UIDevice name/model/systemVersion]` | 返回值字符串 |
| Keychain 读取 | `SecItemCopyMatching` | service + account + data |
| Keychain 写入 | `SecItemAdd / SecItemUpdate` | 高德在写哪些 key |
| NSUserDefaults | `objectForKey:` | 高德读的设备相关 key |
| DTHbalSe 额外采集 | `sysctlbyname` 参数 | hw.machine / hw.model 等 |

**产出**：所有采集点列表 → 写入 `Reverse/notes/分析报告.md`

---

### RT-3｜登录态存储位置（依赖 RT-1）
**目标**：找到高德登录 token / Cookie / session 的存储位置
| 存储类型 | 定位手段 | 关注内容 |
|---------|---------|---------|
| Keychain | Hook `SecItemAdd` 打印 service/account | auth token、uid |
| Cookie | Hook `NSHTTPCookieStorage setCookie:` | 域名、字段名 |
| NSUserDefaults | Hook `setObject:forKey:` | 登录相关 key |
| SQLite | 扫描沙盒 Documents/Library 下 .db 文件 | 用户表、session 表 |

**产出**：登录态字段清单 → `backup.py` / `restore.py` 据此实现

---

### RT-4｜风控上报字段验证（依赖 RT-2，用于验收）
**目标**：抓包对比新旧设备请求，验证伪装后服务端认为是新设备
| 验证点 | 手段 |
|--------|------|
| 风控上报接口 URL | mitmproxy 抓包 + SSL Kill Switch 解密 |
| 请求体设备字段 | 对比伪装前后 diff |
| 服务端响应标记 | 是否返回"新设备"或触发验证 |

**产出**：`Reverse/samples/` 存抓包文件，`Reverse/notes/分析报告.md` 记录结论

---

### 不需要逆向的内容
| 内容 | 原因 |
|------|------|
| 高德地图业务逻辑（导航/搜索） | 与新机无关 |
| TinyDingRTC 框架 | 音视频通话，无关 |
| DTHbalSe 内 MNN 神经网络模型 | 只需绕过，不需理解模型 |
| FairPlay DRM | 越狱设备内存中已解密 |

---

## 实施计划（严格按序，禁止跳阶段）

### ✅ 侦察完成

### ✅ 阶段一：突破 DTHbalSe Frida 检测（完成）
**目标**: Frida 能稳定 attach 并运行 10 秒以上不被踢出
**步骤**:
1. spawn 暂停状态枚举 DTHbalSe 全量 imports/exports
2. 定位检测点：`sysctlbyname` 调用路径 + 端口探测（27042）+ maps 扫描
3. 写 `bypass.js`：Hook 检测函数，返回"安全"结果
4. 验证：attach 后稳定运行

**交付文件**: `Reverse/output/scripts/frida/bypass.js`

---

### 🔄 阶段二：设备指纹 Hook 引擎（当前）
**目标**: 所有设备 ID API 返回 profile.json 中的伪装值
**Hook 目标**:
- `[UIDevice identifierForVendor]` → IDFV
- `ASIdentifierManager.advertisingIdentifier` → IDFA
- `[UIDevice name]` / `[UIDevice model]` / `[UIDevice systemVersion]`
- `CTTelephonyNetworkInfo` → 运营商信息
- `SecItemCopyMatching` → 拦截 Keychain 读取
- `SecItemAdd / SecItemUpdate` → 拦截 Keychain 写入
- `[NSUserDefaults objectForKey:]` → 拦截高德缓存设备ID

**交付文件**: `Reverse/output/scripts/frida/spoof.js`, `Reverse/output/profiles/new_device.json`

---

### ❌ 阶段三：备份 & 还原系统
**目标**: 一键保存伪装环境 + 高德登录态；一键还原
**备份内容**:
```json
{
  "device": { "idfv": "...", "idfa": "...", "model": "...", "name": "..." },
  "keychain": [ { "service": "...", "account": "...", "data": "..." } ],
  "userdefaults": { "key": "value" },
  "cookies": [ { "name": "...", "value": "...", "domain": "..." } ]
}
```
**交付文件**: `Reverse/output/scripts/python/backup.py`, `restore.py`

---

### 🔄 阶段四：Theos Tweak 封装（源码完成，待 macOS/Linux 编译）
**目标**: 编译 .deb 安装到 Dopamine，开机自动生效，无需 Frida
**交付文件**: `Reverse/output/tweak/`（10 个源文件已完成）
**编译指令**: 在 macOS/Linux Theos 环境中 `cd Reverse/output/tweak && make package`

---

## 交付验收标准（全部满足才算完成）

以下四项必须在真机上同时通过，缺一不可：

| # | 验收项 | 验证方法 | 说明 |
|---|--------|---------|------|
| 1 | **商家团购可见** | 搜索周边商家，详情页有「团购」入口 | App 功能正常，未因指纹伪装导致功能降级 |
| 2 | **三网卡注册通过** | 用中国移动/联通/电信各一张手机号注册，三次均成功 | 新机后每个号码都能正常走注册流程 |
| 3 | **新机可重复注册** | 三次注册完成后再执行一次新机，继续注册新号码仍成功 | 证明设备指纹大概率通过风控（可循环新机） |
| 4 | **搜索点位不掉登录** | 登录后搜索多个 POI（地点/商家），登录态持续稳定 | spoof 不破坏正常网络请求，Session 不被踢出 |

> **判断依据**：验收项 3 通过 = 设备指纹已绕过（服务端把每次新机后的设备当作全新设备）；  
> 验收项 1 + 4 通过 = App 功能完整，无副作用。

---

## 开发铁律

### 双架构兼容规则（强制，所有构建产物必须满足）
IPA 和 deb 必须同时兼容 arm64（A11 及以下）和 arm64e（A12+）机型：
1. **Makefile 必须包含** `ARCHS = arm64 arm64e`，禁止只写 arm64
2. **MH 宏必须 strip PAC**：bypass.mm 的 `MH` 宏对 arm64e 的 PAC 签名指针做 strip 后再传给 MSHookFunction，防止 hook 失效/崩溃
3. **构建环境要求**：必须在 A12+（arm64e）设备上、macOS Theos 或 GitHub Actions macOS runner 上构建，arm64-only 设备构建的产物禁止发布
4. **验证方法**：`lipo -archs <binary>` 必须同时输出 `arm64 arm64e`；缺任一架构的产物禁止放入 `dist/`

### dist/ 版本编号规则（强制）
每次编译输出新文件到 `dist/` 时：
1. 查找当前 `dist/` 里同类文件的最大版本号（格式 `_vN`）
2. 新文件命名加 `_v{N+1}`，例如：
   - IPA：`YiJianXinJi_v1.ipa` → `YiJianXinJi_v2.ipa`
   - deb：`com.dev.amapnewdevice_1.0.0_iphoneos-arm64_v1.deb` → `_v2.deb`
3. **保留旧版本，不删除**，便于回滚对比
4. 若当前无版本号文件，从 `_v1` 开始

### Frida 脚本分工（严格，禁止混写）
| 文件 | 职责 |
|------|------|
| `bypass.js` | 只写绕过 DTHbalSe 检测的 Hook |
| `spoof.js` | 只写设备指纹伪装 Hook |
| `debug/` | 一次性探测，用完删 |

### 编译构建规范（强制）

**优先用本地编译（deploy.py）**，GitHub Actions CI 作为备用：

```
本地编译（推荐）：python deploy.py
CI 编译（备用）：git push → GitHub Actions 自动触发
```

#### deploy.py 本地编译流程
`deploy.py` 通过 SSH 127.0.0.1:3333（iproxy 转发设备端口）完成：
上传修改文件 → on-device make package FINALPACKAGE=1 → 拉回 dist/tweak_vN.deb
**不自动安装到设备**，用户自行用 Filza / Sileo / `dpkg -i` 安装

**前置条件（缺一不可）**：
1. 设备通过 USB 连接，`iproxy 3333 22` 正在运行（或已 adb forward tcp:3333 tcp:22）
2. 设备端 Theos 已安装在 `/var/jb/opt/theos`
3. `pip install paramiko`

```bash
# 确认 iproxy 转发
iproxy 3333 22 &

# 一键编译安装
python deploy.py

# 仅检查日志（不重编）
python deploy.py --check
```

**CHANGED 文件列表**：`deploy.py` 顶部的 `CHANGED` 数组控制上传哪些文件。改了哪些 tweak 源文件就更新对应条目，**不要漏传也不要多传**。当前包含：
`bypass.mm / profile.h / profile.mm / spoof.mm / tlog.mm / Tweak.x`

IPA 构建（ios_app_oc）**不走 deploy.py**，走 CI：改 ios_app_oc/ 后 push，CI 自动出 IPA。

#### 编译产物命名
- 本地编译产出：`dist/tweak_vN.deb`（N 自动递增，deploy.py 自动计算）
- CI 产出：`dist/tweak_vN.deb` + `dist/YiJianXinJi_vN.ipa`（改 ios_app_oc/ 后 push 触发）

---

### 连接规范
```bash
# 连接前确认设备在线
python -c "import frida; print([d for d in frida.enumerate_devices() if 'Apple' in d.name])"

# spawn 模式（阶段一完成后标准启动方式）
frida -D fcb0b05ae20229767149e98cb3ac94dcde52f74f \
  -f com.autonavi.amap \
  -l Reverse/output/scripts/frida/bypass.js \
  -l Reverse/output/scripts/frida/spoof.js \
  --no-pause
```

### 其他规范
- `spoof.js` 所有返回值从 `profiles/active.json` 读取，**禁止硬编码**
- 探测脚本放 `debug/` 并注释 `// 一次性，用完删`
- **Windows 下用 `python` 不用 `python3`**
- 改代码前先列改动方案，等确认再动手

---

## 日志规范（强制执行）

### 1. 开发日志 `Reverse/notes/开发日志.md`
**更新时机**：每完成一个阶段 / 每次写完或修改代码文件后，**当回复末尾必须追加**。

格式：
```
## YYYY-MM-DD
### <类型>: <简述>
- 文件：`路径/文件名` +新增行/-删除行
- 改动：具体改了什么
- 原因：为什么改
```
类型：`recon`（侦察）/ `bypass`（检测绕过）/ `spoof`（指纹伪装）/ `backup`（备份还原）/ `tweak`（封装）/ `fix`（修复）

---

### 2. 分析报告 `Reverse/notes/分析报告.md`
**更新时机**：每个逆向目标（RT-1~RT-4）完成后，**当回复末尾同步**。

固定格式：
```markdown
# 高德地图 16.02.1 逆向分析报告

## 这个程序是干什么的
一句话说清楚

## 发现了什么
- 请求/检测逻辑
- 加密/签名情况
- 关键函数位置

## 需要逆向的点
状态：✅ 已完成　🔄 进行中　❌ 未开始
- ✅ RT-1 DTHbalSe 检测绕过
- ✅ RT-2 设备指纹采集点
- ...

## 当前进度

## 关键数据
（IDFV / Keychain key / UD key 等已发现的值）

## 怎么复现

## 还没搞清楚的
```

---

### 3. 写完/改完代码后必须输出 `[PRE-BUILD REVIEW]`
```
[PRE-BUILD REVIEW]
本文件: ✅/❌ <结论>
关联文件: ✅/❌ <结论>
冗长度: ✅/❌ <最长函数行数 | 注释情况>
结论: 通过/不通过
```

---

### 4. 阶段完成标准
每个阶段必须同时满足：
| 项目 | 要求 |
|------|------|
| 功能验证 | Frida 运行证据 / 输出截图 |
| 开发日志 | `开发日志.md` 已追加当次记录 |
| 分析报告 | `分析报告.md` 对应 RT 状态已更新 |
| CLAUDE.md | 阶段状态从 🔄 改为 ✅ |

缺任意一项 → 不得宣告完成
