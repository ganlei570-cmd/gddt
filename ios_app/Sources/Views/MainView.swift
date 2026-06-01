import SwiftUI
import UIKit

struct MainView: View {
    @EnvironmentObject var authState: AuthState
    @StateObject private var pm = ProfileManager.shared
    @State private var toast   = ""
    @State private var showToast = false
    @State private var showBackup = false
    @State private var restoreMode = false

    var body: some View {
        ZStack(alignment: .bottom) {
            Color(hex: "1C1E2A").ignoresSafeArea()
            ScrollView {
                VStack(spacing: 10) {
                    toolbar
                    togglesCard
                    deviceCard
                    appCard
                    buttonGrid
                    footer
                }
                .padding(.horizontal, 14)
                .padding(.top, 14)
                .padding(.bottom, 24)
            }
            if showToast {
                Text(toast)
                    .font(.system(size: 13)).foregroundColor(.white)
                    .padding(.horizontal, 18).padding(.vertical, 10)
                    .background(Color(hex: "252538").opacity(0.95))
                    .cornerRadius(20)
                    .padding(.bottom, 40)
                    .transition(.opacity)
            }
        }
        .sheet(isPresented: $showBackup) {
            BackupView(restoreMode: restoreMode)
                .environmentObject(pm)
        }
    }

    // MARK: - Toolbar
    var toolbar: some View {
        HStack {
            Button("安全退出") { authState.isLoggedIn = false }
                .font(.system(size: 12)).foregroundColor(Color(hex: "8B8FA8"))
            Spacer()
            Text("一键新机").font(.system(size: 17, weight: .bold)).foregroundColor(.white)
            Spacer()
            Image(systemName: "gearshape").foregroundColor(Color(hex: "8B8FA8"))
        }
    }

    // MARK: - Toggles
    var togglesCard: some View {
        Card {
            VStack(spacing: 12) {
                ToggleRow("模拟定位", on: false, enabled: false)
                ToggleRow("随机参数", on: true,  enabled: true)
                ToggleRow("VPN",     on: false, enabled: false)
                HStack {
                    Text("新机参数").font(.system(size: 14)).foregroundColor(.white)
                    Spacer()
                    Text("配置").font(.system(size: 12)).foregroundColor(Color(hex: "8B8FA8"))
                        .padding(.horizontal, 14).padding(.vertical, 6)
                        .background(Color(hex: "353649")).cornerRadius(8)
                }
            }
        }
    }

    // MARK: - Device info
    var deviceCard: some View {
        Card {
            HStack(spacing: 12) {
                Text("📱").font(.system(size: 30))
                VStack(alignment: .leading, spacing: 3) {
                    Text(UIDevice.current.model)
                        .font(.system(size: 14, weight: .semibold)).foregroundColor(.white)
                    Text("iOS \(UIDevice.current.systemVersion)  IDFV: \(pm.activeIdfv.isEmpty ? "未设置" : String(pm.activeIdfv.prefix(8)))…")
                        .font(.system(size: 11)).foregroundColor(Color(hex: "8B8FA8"))
                }
                Spacer()
            }
        }
    }

    // MARK: - App section
    var appCard: some View {
        Card {
            VStack(spacing: 10) {
                HStack {
                    Text("应用列表[1]").font(.system(size: 11)).foregroundColor(Color(hex: "8B8FA8"))
                    Spacer()
                    Text("高德地图").font(.system(size: 11)).foregroundColor(Color(hex: "8B8FA8"))
                }
                HStack(spacing: 24) {
                    ToggleRow("保存参数", on: true, enabled: true)
                    ToggleRow("全息备份", on: true, enabled: true)
                    Spacer()
                }
            }
        }
    }

    // MARK: - Button grid
    var buttonGrid: some View {
        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())],
                  spacing: 8) {
            ActionBtn("一键新机",    enabled: true)  { doNewMachine() }
            ActionBtn("清理Safari",  enabled: true)  { doClearSafari() }
            ActionBtn("备份记录",    enabled: true)  { restoreMode = false; showBackup = true }
            ActionBtn("清理剪贴板",  enabled: true)  { doClearClipboard() }
            ActionBtn("清理Keychain",enabled: true)  { doClearKeychain() }
            ActionBtn("还原机器",    enabled: true)  { restoreMode = true; showBackup = true }
        }
    }

    // MARK: - Footer
    var footer: some View {
        HStack {
            Text("v1.0.0").font(.system(size: 11)).foregroundColor(Color(hex: "8B8FA8"))
            Spacer()
            Text("充值").font(.system(size: 12)).foregroundColor(Color(hex: "F97316")).opacity(0.4)
            Text("免责声明").font(.system(size: 12)).foregroundColor(Color(hex: "2563EB"))
        }
        .padding(.top, 4)
    }

    // MARK: - Actions
    private func doNewMachine() {
        do {
            let p = try pm.newMachine()
            showToast("新机完成\nIDFV: \(p.idfv.prefix(8))…\n请重启高德地图")
        } catch {
            showToast("失败: \(error.localizedDescription)")
        }
    }

    private func doClearKeychain() {
        do {
            var p = ProfileManager.shared.loadActive() ?? Profile.generate()
            p.keychain = Dictionary(uniqueKeysWithValues: p.keychain.keys.map { ($0, "CLEAR") })
            try pm.saveActive(p)
            showToast("Keychain 已清理\n请重启高德地图")
        } catch {
            showToast("失败: \(error.localizedDescription)")
        }
    }

    private func doClearSafari() {
        let path = "/var/mobile/Library/Cookies/com.apple.SafariShared.WebKit.Cookies.binarycookies"
        do {
            try FileManager.default.removeItem(atPath: path)
            showToast("Safari 已清理\n请重启 Safari")
        } catch {
            showToast("清理失败: \(error.localizedDescription)")
        }
    }

    private func doClearClipboard() {
        UIPasteboard.general.items = []
        showToast("剪贴板已清理")
    }

    private func showToast(_ msg: String) {
        toast = msg; showToast = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { showToast = false }
    }
}

// MARK: - Sub-components

struct Card<Content: View>: View {
    let content: Content
    init(@ViewBuilder _ content: () -> Content) { self.content = content() }
    var body: some View {
        content.padding(14)
            .background(Color(hex: "252538"))
            .cornerRadius(12)
    }
}

struct ToggleRow: View {
    let label: String
    @State var on: Bool
    let enabled: Bool
    init(_ label: String, on: Bool, enabled: Bool) {
        self.label = label; _on = State(initialValue: on); self.enabled = enabled
    }
    var body: some View {
        HStack {
            Text(label).font(.system(size: 14)).foregroundColor(enabled ? .white : Color(hex: "8B8FA8"))
            Spacer()
            XBToggle(on: $on, enabled: enabled)
        }
    }
}

struct XBToggle: View {
    @Binding var on: Bool
    let enabled: Bool
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 15.5)
                .fill(enabled && on ? Color(hex: "22C55E") : Color(hex: "3A3B50"))
                .frame(width: 51, height: 31)
            Circle().fill(.white).frame(width: 23)
                .offset(x: on ? 12 : -12)
                .animation(.spring(response: 0.2, dampingFraction: 0.7), value: on)
        }
        .onTapGesture { if enabled { on.toggle() } }
    }
}

struct ActionBtn: View {
    let title: String
    let enabled: Bool
    let action: () -> Void
    init(_ title: String, enabled: Bool, action: @escaping () -> Void) {
        self.title = title; self.enabled = enabled; self.action = action
    }
    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 13))
                .foregroundColor(enabled ? .white : Color(hex: "8B8FA8"))
                .frame(maxWidth: .infinity)
                .frame(height: 44)
                .background(Color(hex: enabled ? "353649" : "252535"))
                .cornerRadius(10)
        }
        .disabled(!enabled)
    }
}

extension Color {
    init(hex: String) {
        var h = hex.trimmingCharacters(in: .alphanumerics.inverted)
        if h.count == 6 { h = "FF" + h }
        var n: UInt64 = 0; Scanner(string: h).scanHexInt64(&n)
        self.init(red: Double((n >> 16) & 0xFF)/255,
                  green: Double((n >> 8) & 0xFF)/255,
                  blue: Double(n & 0xFF)/255)
    }
}
