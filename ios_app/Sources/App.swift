import SwiftUI

@main
struct AmapNewMachineApp: App {
    @StateObject private var authState = AuthState()

    var body: some Scene {
        WindowGroup {
            Group {
                if authState.isLoggedIn {
                    MainView().environmentObject(authState)
                } else {
                    LoginView().environmentObject(authState)
                }
            }
            .preferredColorScheme(.dark)
        }
    }
}

@MainActor
class AuthState: ObservableObject {
    @Published var isLoggedIn = false

    init() {
        let cached = XBZhanAuth.shared.loadCachedKey()
        guard !cached.isEmpty else { return }
        Task {
            let (ok, _) = await XBZhanAuth.shared.login(cardKey: cached)
            self.isLoggedIn = ok
        }
    }
}
