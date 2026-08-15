import Foundation
import Security

enum DemoCrypto {
    static let entropyKey = "engytita.demo.entropy64"

    /// Demo-quality persistence only — not a secure enclave story.
    static func loadOrCreateEntropy() -> Data {
        if let existing = UserDefaults.standard.data(forKey: entropyKey), existing.count == 64 {
            return existing
        }
        var bytes = [UInt8](repeating: 0, count: 64)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        let data = Data(bytes)
        UserDefaults.standard.set(data, forKey: entropyKey)
        return data
    }

    static func randomBytes(_ n: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: n)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return Data(bytes)
    }

    static func currentEpoch() -> UInt64 {
        let seconds = UInt64(Date().timeIntervalSince1970)
        return seconds / epochSeconds()
    }
}
