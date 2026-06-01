import SwiftUI

struct BackupView: View {
    let restoreMode: Bool
    @EnvironmentObject var pm: ProfileManager
    @Environment(\.dismiss) private var dismiss
    @State private var items: [BackupItem] = []
    @State private var selected: BackupItem?
    @State private var toast = ""
    @State private var showToast = false

    var body: some View {
        ZStack(alignment: .bottom) {
            Color(hex: "1C1E2A").ignoresSafeArea()
            VStack(spacing: 0) {
                header
                if items.isEmpty {
                    Spacer()
                    Text("暂无备份").foregroundColor(Color(hex: "8B8FA8")).font(.system(size: 14))
                    Spacer()
                } else {
                    List(items) { item in
                        BackupRow(item: item, selected: selected?.id == item.id)
                            .onTapGesture { selected = item }
                            .listRowBackground(Color(hex: selected?.id == item.id ? "353649" : "252538"))
                            .listRowSeparatorTint(Color(hex: "333448"))
                    }
                    .listStyle(.plain)
                    .background(Color(hex: "252538"))
                    .cornerRadius(12)
                    .padding(.horizontal, 14)
                }
                toolbar
            }
            if showToast {
                Text(toast).font(.system(size: 13)).foregroundColor(.white)
                    .padding(.horizontal, 18).padding(.vertical, 10)
                    .background(Color(hex: "252538").opacity(0.95))
                    .cornerRadius(20).padding(.bottom, 80)
                    .transition(.opacity)
            }
        }
        .onAppear { items = pm.listBackups() }
    }

    var header: some View {
        HStack {
            Text(restoreMode ? "选择要还原的备份" : "备份管理[\(items.count)]")
                .font(.system(size: 16, weight: .bold)).foregroundColor(.white)
            Spacer()
            if !restoreMode {
                Button("+ 新建") { doNew() }
                    .font(.system(size: 13))
                    .padding(.horizontal, 14).padding(.vertical, 7)
                    .background(Color(hex: "2563EB")).cornerRadius(8)
                    .foregroundColor(.white)
            }
        }
        .padding(.horizontal, 14).padding(.top, 20).padding(.bottom, 10)
    }

    var toolbar: some View {
        HStack(spacing: 8) {
            if !restoreMode {
                TBtn("删除", color: "EF4444") { doDelete() }
            }
            TBtn(restoreMode ? "还原" : "还原选中", color: "22C55E") { doRestore() }
            TBtn("关闭", color: "3A3B50") { dismiss() }
        }
        .padding(.horizontal, 14).padding(.vertical, 12)
        .background(Color(hex: "1C1E2A"))
    }

    private func doNew() {
        do {
            let name = try pm.backup()
            items = pm.listBackups()
            flash("备份成功: \(name)")
        } catch { flash("失败: \(error.localizedDescription)") }
    }

    private func doDelete() {
        guard let s = selected else { flash("请先选择一个备份"); return }
        do {
            try pm.delete(path: s.path)
            items = pm.listBackups()
            selected = nil
            flash("已删除")
        } catch { flash("失败: \(error.localizedDescription)") }
    }

    private func doRestore() {
        guard let s = selected else { flash("请先选择一个备份"); return }
        do {
            try pm.restore(from: s.path)
            flash("还原成功，请重启高德地图")
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { dismiss() }
        } catch { flash("失败: \(error.localizedDescription)") }
    }

    private func flash(_ msg: String) {
        toast = msg; showToast = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { showToast = false }
    }
}

struct BackupRow: View {
    let item: BackupItem
    let selected: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(item.name).font(.system(size: 13, weight: .medium)).foregroundColor(.white)
            Text("IDFV: \(item.idfv.prefix(18))…  \(item.date)  \(item.size/1024)KB")
                .font(.system(size: 11)).foregroundColor(Color(hex: "8B8FA8"))
        }
        .padding(.vertical, 4)
        .overlay(alignment: .trailing) {
            if selected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(Color(hex: "22C55E"))
            }
        }
    }
}

struct TBtn: View {
    let title: String; let color: String; let action: () -> Void
    var body: some View {
        Button(title, action: action)
            .font(.system(size: 13)).foregroundColor(.white)
            .frame(maxWidth: .infinity).frame(height: 42)
            .background(Color(hex: color)).cornerRadius(10)
    }
}
