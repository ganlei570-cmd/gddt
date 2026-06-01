import Foundation

private let PROFILE_DIR = "/var/mobile/Documents/amap_profiles"
private let ACTIVE_PATH = PROFILE_DIR + "/active.json"
private let KC_KEYS = [
    "com.autonavi.amap/udid", "com.autonavi.amap/vimsi", "com.autonavi.amap/vimei",
    "com.autonavi.amap/tid", "com.autonavi.amap/public_key", "gd_amap/gd_amap",
    "com.amap.adiu.key/com.amap.adiu.key", "0.umid_v1/com.autonavi.amap",
    "PNS_UniqueId_com.autonavi.amap/PNS_UniqueId_com.autonavi.amap"
]

struct Profile: Codable, Identifiable {
    var id: String { idfv }
    var idfv: String
    var idfa: String
    var keychain: [String: String]
    var userdefaults: [String: String?]

    static func generate() -> Profile {
        let idfv = UUID().uuidString.uppercased()
        let kc = Dictionary(uniqueKeysWithValues: KC_KEYS.map { ($0, "CLEAR") })
        let ud: [String: String?] = [
            "__AMAP_APP_FIRST__": nil, "appInitMd5": nil,
            "login_credit": nil, "ATAuthSDK_POP_com.autonavi.amap": nil
        ]
        return Profile(idfv: idfv, idfa: "00000000-0000-0000-0000-000000000000",
                       keychain: kc, userdefaults: ud)
    }
}

struct BackupItem: Identifiable {
    let id = UUID()
    let name: String
    let path: String
    let idfv: String
    let date: String
    let size: Int
}

final class ProfileManager: ObservableObject {
    static let shared = ProfileManager()

    @Published var activeIdfv: String = ""

    init() { reload() }

    func reload() {
        guard let p = loadActive() else { return }
        activeIdfv = p.idfv
    }

    // MARK: - Active profile
    func loadActive() -> Profile? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: ACTIVE_PATH)) else { return nil }
        return try? JSONDecoder().decode(Profile.self, from: data)
    }

    func saveActive(_ profile: Profile) throws {
        try FileManager.default.createDirectory(
            atPath: PROFILE_DIR, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(profile)
        try data.write(to: URL(fileURLWithPath: ACTIVE_PATH))
        activeIdfv = profile.idfv
    }

    // MARK: - New machine
    func newMachine() throws -> Profile {
        let p = Profile.generate()
        try saveActive(p)
        return p
    }

    // MARK: - Backups
    func listBackups() -> [BackupItem] {
        let dir = URL(fileURLWithPath: PROFILE_DIR)
        guard let files = try? FileManager.default.contentsOfDirectory(
            at: dir, includingPropertiesForKeys: [.fileSizeKey, .contentModificationDateKey]
        ) else { return [] }

        return files
            .filter { $0.lastPathComponent.hasPrefix("高德地图_") && $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .compactMap { url -> BackupItem? in
                guard let data = try? Data(contentsOf: url),
                      let p = try? JSONDecoder().decode(Profile.self, from: data),
                      let attrs = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
                else { return nil }
                let fmt = DateFormatter()
                fmt.dateFormat = "MM-dd HH:mm"
                let date = fmt.string(from: attrs.contentModificationDate ?? Date())
                return BackupItem(
                    name: String(url.lastPathComponent.dropLast(5)),
                    path: url.path, idfv: p.idfv,
                    date: date, size: attrs.fileSize ?? 0)
            }
    }

    func backup() throws -> String {
        let items = listBackups()
        let nums = items.compactMap { Int($0.name.split(separator: "_").last ?? "") }
        let n = (nums.max() ?? 0) + 1
        let name = String(format: "高德地图_%05d", n)
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: ACTIVE_PATH)) else {
            throw NSError(domain: "ProfileManager", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "尚无 active.json"])
        }
        let dest = "\(PROFILE_DIR)/\(name).json"
        try data.write(to: URL(fileURLWithPath: dest))
        return name
    }

    func restore(from path: String) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let p = try JSONDecoder().decode(Profile.self, from: data)
        try saveActive(p)
    }

    func delete(path: String) throws {
        try FileManager.default.removeItem(atPath: path)
    }
}
