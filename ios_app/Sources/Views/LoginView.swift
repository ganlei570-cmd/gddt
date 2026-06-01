import SwiftUI

struct LoginView: View {
    @EnvironmentObject var authState: AuthState
    @State private var cardKey = ""
    @State private var errMsg  = ""
    @State private var loading = false
    @State private var unbindMsg = ""

    var body: some View {
        ZStack {
            Color(hex: "1C1E2A").ignoresSafeArea()
            VStack(spacing: 0) {
                Spacer()
                VStack(spacing: 20) {
                    Text("一键新机").font(.system(size: 28, weight: .bold)).foregroundColor(.white)
                    Text("输入卡密以继续").font(.system(size: 13)).foregroundColor(Color(hex: "8B8FA8"))
                    TextField("请输入卡密", text: $cardKey)
                        .padding(.horizontal, 14).padding(.vertical, 12)
                        .background(Color(hex: "252538"))
                        .cornerRadius(10)
                        .foregroundColor(.white)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .onSubmit { doLogin() }

                    if !errMsg.isEmpty {
                        Text(errMsg).font(.system(size: 12))
                            .foregroundColor(Color(hex: "EF4444"))
                    }
                    if !unbindMsg.isEmpty {
                        Text(unbindMsg).font(.system(size: 12))
                            .foregroundColor(Color(hex: "22C55E"))
                    }

                    Button(action: doLogin) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 12)
                                .fill(loading ? Color(hex: "2A2B3A") : Color(hex: "2563EB"))
                            if loading {
                                ProgressView().tint(.white)
                            } else {
                                Text("登 录").font(.system(size: 16, weight: .semibold))
                                    .foregroundColor(.white)
                            }
                        }
                        .frame(height: 50)
                    }
                    .disabled(loading)

                    Button("解绑当前设备") { doUnbind() }
                        .font(.system(size: 12))
                        .foregroundColor(Color(hex: "8B8FA8"))
                }
                .padding(.horizontal, 28)
                Spacer()
            }
        }
        .onAppear {
            cardKey = XBZhanAuth.shared.loadCachedKey()
        }
    }

    private func doLogin() {
        let key = cardKey.trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty else { errMsg = "请输入卡密"; return }
        errMsg = ""; unbindMsg = ""; loading = true
        Task {
            let (ok, msg) = await XBZhanAuth.shared.login(cardKey: key)
            await MainActor.run {
                loading = false
                if ok { authState.isLoggedIn = true }
                else  { errMsg = msg }
            }
        }
    }

    private func doUnbind() {
        let key = cardKey.trimmingCharacters(in: .whitespaces)
        guard !key.isEmpty else { errMsg = "请先输入卡密"; return }
        errMsg = ""; unbindMsg = ""; loading = true
        Task {
            let (ok, msg) = await XBZhanAuth.shared.unbindAll(cardKey: key)
            await MainActor.run {
                loading = false
                if ok { unbindMsg = "解绑成功，可在新设备登录" }
                else  { errMsg = msg }
            }
        }
    }
}
