import Foundation
import CommonCrypto
import UIKit

private let SOFT          = "N7vfi8ZKGlXO2SArgC"
private let SOFT_KEY      = "GC6tgXFhCreKn7s323CLtENVyP4CYsih"
private let RC4_KEY       = "BzDNbwMVTaVLqEWD4E2ISoA4dn9w0LCyLXfbup9Uj93asD6z"
private let SIGN_TEMPLATE = "123[data]456[key]789"
private let VERSION       = "1.0"
private let API_BASE      = "http://api2.xbzhan.com"
private let CACHE_KEY     = "xb_cached_card_key"
private let HB_INTERVAL: TimeInterval = 120

final class XBZhanAuth: ObservableObject {
    static let shared = XBZhanAuth()

    private(set) var cardKey = ""
    private var sessionCookie = ""
    private var initialized = false
    private var hbTimer: Timer?

    // MARK: - RC4
    private func rc4(_ data: Data, key: Data) -> Data {
        var S = (0...255).map { UInt8($0) }
        var j = 0
        for i in 0...255 {
            j = (j + Int(S[i]) + Int(key[i % key.count])) % 256
            S.swapAt(i, j)
        }
        var i = 0; j = 0
        return Data(data.map { byte in
            i = (i + 1) % 256
            j = (j + Int(S[i])) % 256
            S.swapAt(i, j)
            return byte ^ S[(Int(S[i]) + Int(S[j])) % 256]
        })
    }

    private func md5(_ s: String) -> String {
        let d = Data(s.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        d.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(d.count), &digest) }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Device fingerprint
    private func buildBase() -> [String: Any] {
        let hostname = ProcessInfo.processInfo.hostName
        let mac = hostname + UIDevice.current.identifierForVendor!.uuidString
        let macHash = String(md5(mac).prefix(12)).uppercased()
        let featureHash = String(md5(mac + UIDevice.current.systemVersion).prefix(16)).uppercased()
        let clientid = String(md5(mac).prefix(18)).uppercased()
        return [
            "uuid": UUID().uuidString.replacingOccurrences(of: "-", with: ""),
            "token": UUID().uuidString.replacingOccurrences(of: "-", with: ""),
            "clientid": clientid, "version": VERSION,
            "mac": macHash, "feature": featureHash,
            "clientos": "iOS \(UIDevice.current.systemVersion)", "md5": ""
        ]
    }

    // MARK: - API
    private func post(_ path: String, data: [String: Any]) async -> [String: Any] {
        guard let dataJSON = try? JSONSerialization.data(
            withJSONObject: data, options: [.sortedKeys]) else {
            return ["code": -1, "msg": "序列化失败"]
        }
        let compact = String(data: dataJSON, encoding: .utf8) ?? "{}"
        let encData = rc4(Data(compact.utf8), key: Data(RC4_KEY.utf8))
        let encHex  = encData.map { String(format: "%02x", $0) }.joined()
        let signStr = SIGN_TEMPLATE
            .replacingOccurrences(of: "[data]", with: encHex)
            .replacingOccurrences(of: "[key]",  with: SOFT_KEY)
        let sign = md5(signStr)
        let body: [String: Any] = ["soft": SOFT, "data": encHex, "sign": sign]
        guard let bodyData = try? JSONSerialization.data(withJSONObject: body),
              let url = URL(string: API_BASE + path) else {
            return ["code": -1, "msg": "构建请求失败"]
        }
        var req = URLRequest(url: url, timeoutInterval: 10)
        req.httpMethod = "POST"
        req.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        req.httpBody = bodyData
        do {
            let (respData, _) = try await URLSession.shared.data(for: req)
            guard let outer = try? JSONSerialization.jsonObject(with: respData) as? [String: Any],
                  outer["status"] as? String == "success",
                  let hexStr = outer["data"] as? String else {
                return ["code": -1, "msg": "请求异常"]
            }
            let hexBytes = stride(from: 0, to: hexStr.count, by: 2).compactMap { i -> UInt8? in
                let s = hexStr.index(hexStr.startIndex, offsetBy: i)
                let e = hexStr.index(s, offsetBy: 2, limitedBy: hexStr.endIndex) ?? hexStr.endIndex
                return UInt8(hexStr[s..<e], radix: 16)
            }
            let decData = rc4(Data(hexBytes), key: Data(RC4_KEY.utf8))
            return (try? JSONSerialization.jsonObject(with: decData) as? [String: Any]) ?? [:]
        } catch {
            return ["code": -1, "msg": "网络错误: \(error.localizedDescription)"]
        }
    }

    // MARK: - Public API
    func login(cardKey: String) async -> (Bool, String) {
        if !initialized {
            let r = await post("/api/init", data: buildBase())
            initialized = (r["code"] as? Int == 200) || (r["msg"] as? String ?? "").contains("成功")
            if !initialized { return (false, "初始化失败: \(r["msg"] ?? "")") }
        }
        var data = buildBase()
        data["account"] = cardKey
        let resp = await post("/api/login", data: data)
        let ok = (resp["code"] as? Int == 200) || (resp["msg"] as? String ?? "").contains("成功")
        if ok {
            self.cardKey = cardKey
            let result = resp["result"] as? [String: Any] ?? [:]
            self.sessionCookie = (resp["cookie"] as? String)
                ?? (result["loginCookie"] as? String)
                ?? (resp["param"] as? String) ?? ""
            saveCachedKey(cardKey)
            startHeartbeat()
        }
        return (ok, resp["msg"] as? String ?? "未知错误")
    }

    func unbindAll(cardKey: String) async -> (Bool, String) {
        if !initialized { _ = await post("/api/init", data: buildBase()) }
        var data = buildBase()
        data["account"] = cardKey
        let resp = await post("/api/un_bind_all", data: data)
        let ok = (resp["code"] as? Int == 200) || (resp["msg"] as? String ?? "").contains("成功")
        return (ok, resp["msg"] as? String ?? "未知错误")
    }

    // MARK: - Heartbeat
    private func startHeartbeat() {
        hbTimer?.invalidate()
        hbTimer = Timer.scheduledTimer(withTimeInterval: HB_INTERVAL, repeats: true) { [weak self] _ in
            guard let self else { return }
            Task {
                var data = self.buildBase()
                data["account"] = self.cardKey
                data["cookie"]  = self.sessionCookie
                _ = await self.post("/api/heartbeat", data: data)
            }
        }
    }

    // MARK: - Cache
    func loadCachedKey() -> String {
        UserDefaults.standard.string(forKey: CACHE_KEY) ?? ""
    }
    private func saveCachedKey(_ key: String) {
        UserDefaults.standard.set(key, forKey: CACHE_KEY)
    }
}
