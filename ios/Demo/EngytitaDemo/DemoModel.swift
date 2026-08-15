import CoreBluetooth
import Foundation
import Observation

@Observable
@MainActor
final class DemoModel {
    enum Role {
        case idle
        case responder
        case initiator
    }

    var status: String = "Ready"
    var log: [String] = []
    var epoch: UInt64 = 0
    var localEidHex: String = ""
    var peerIdHex: String = ""
    var discovered: [(id: UUID, name: String, peripheral: CBPeripheral)] = []
    var sasPrompt: String?
    var sasEntry: String = ""
    var keysDerived: Bool = false
    var role: Role = .idle

    private var engine: Engytita!
    private let ble = BleStack()
    private var pairing: PairingSession?
    /// When true, outbound pairing bytes use peripheral notify (responder).
    private var actAsPeripheralTransport = false
    private var pendingOutbound: Data?

    init() {
        do {
            let entropy = DemoCrypto.loadOrCreateEntropy()
            engine = try Engytita(entropy: entropy)
            peerIdHex = hex(engine.peerId().bytes)
            refreshBeacon()
            ble.delegate = self
            NotificationCenter.default.addObserver(
                forName: .engytitaDidDiscoverPeer,
                object: nil,
                queue: .main
            ) { [weak self] note in
                guard let self, let p = note.object as? CBPeripheral else { return }
                Task { @MainActor in
                    if !self.discovered.contains(where: { $0.id == p.identifier }) {
                        self.discovered.append((p.identifier, p.name ?? "Engytita peer", p))
                    }
                }
            }
            append("Engine ready. peer_id=\(peerIdHex.prefix(16))…")
        } catch {
            status = "Init failed: \(error)"
        }
    }

    func refreshBeacon() {
        epoch = DemoCrypto.currentEpoch()
        let eid = engine.beaconEid(epoch: epoch)
        localEidHex = hex(eid)
        ble.setLocalEid(eid)
        append("epoch=\(epoch) eid=\(localEidHex)")
    }

    func startAsResponder() {
        role = .responder
        actAsPeripheralTransport = true
        keysDerived = false
        sasPrompt = nil
        do {
            pairing = try engine.startPairingResponder(ephemeral: DemoCrypto.randomBytes(32))
            let ev = pairing!.takeInitialEvent()
            apply(ev)
            ble.startAdvertising()
            status = "Responder: waiting for initiator"
            append("Started pairing as responder")
        } catch {
            status = "Responder start failed: \(error)"
        }
    }

    func startScanAsInitiator() {
        role = .initiator
        actAsPeripheralTransport = false
        keysDerived = false
        sasPrompt = nil
        discovered.removeAll()
        ble.startScanning()
        status = "Initiator: scanning…"
    }

    func connectAndPair(_ peripheral: CBPeripheral) {
        do {
            pairing = try engine.startPairingInitiator(ephemeral: DemoCrypto.randomBytes(32))
            let ev = pairing!.takeInitialEvent()
            // First SendMessage waits until GATT is up.
            if case let .sendMessage(data) = ev {
                pendingOutbound = data
                append("pairing: deferred send \(data.count) bytes")
            } else {
                apply(ev)
            }
            ble.connect(peripheral)
            status = "Connecting to start pairing…"
        } catch {
            status = "Initiator start failed: \(error)"
        }
    }

    func confirmSas() {
        guard let pairing else { return }
        let digits = String(sasEntry.filter(\.isNumber).prefix(6))
        guard digits.count == 6 else {
            status = "Enter exactly 6 digits"
            return
        }
        do {
            let ev = try pairing.confirmSas(digits: digits)
            sasPrompt = nil
            apply(ev)
        } catch {
            status = "confirmSas failed: \(error)"
            append("SAS error: \(error)")
        }
    }

    func rejectSas() {
        guard let pairing else { return }
        let ev = pairing.rejectSas()
        sasPrompt = nil
        apply(ev)
    }

    private func requestAndAccept(peer: PeerId) {
        do {
            try engine.requestSession(peerId: peer)
            try engine.acceptSession(peerId: peer)
            let keys = try engine.sessionKeys(peerId: peer, nonce: DemoCrypto.randomBytes(16))
            keysDerived = keys.stsKey.count == 16 && keys.transportKey.count == 32
            status = keysDerived ? "Session accepted — keys derived (not logged)" : "Key length mismatch"
            append("session keys ok=\(keysDerived)")
        } catch {
            status = "Session failed: \(error)"
        }
    }

    private func apply(_ event: PairingEvent) {
        switch event {
        case .awaitingMessage:
            append("pairing: awaiting message")
        case let .sendMessage(data):
            append("pairing: send \(data.count) bytes")
            sendOutbound(data)
            // Final handshake / final IRK flights need poll() after transmit.
            tryPollAfterSend()
        case let .confirmSas(digits):
            sasPrompt = digits
            sasEntry = ""
            status = "Confirm SAS out-of-band, then type digits"
            append("SAS displayed — type the digits you confirmed")
        case let .complete(peerId):
            append("Pairing complete peer=\(hex(peerId.bytes).prefix(16))…")
            status = "Paired — deriving session keys"
            requestAndAccept(peer: peerId)
        case let .failed(message):
            status = "Pairing failed: \(message)"
            append("fail: \(message)")
        }
    }

    private func tryPollAfterSend() {
        guard let pairing else { return }
        let polled = pairing.poll()
        switch polled {
        case .failed(let message) where message.contains("invalid"):
            return
        case .awaitingMessage:
            return
        default:
            apply(polled)
        }
    }

    private func sendOutbound(_ data: Data) {
        if actAsPeripheralTransport {
            ble.notifyPairingBytes(data)
        } else {
            ble.writePairingBytes(data)
        }
    }

    private func flushPendingOutbound() {
        if let pending = pendingOutbound {
            pendingOutbound = nil
            sendOutbound(pending)
            append("Flushed deferred initiator message")
            tryPollAfterSend()
        }
    }

    private func append(_ line: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        log.insert("[\(stamp)] \(line)", at: 0)
        if log.count > 80 { log = Array(log.prefix(80)) }
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

extension DemoModel: BleStackDelegate {
    nonisolated func bleDidUpdateStatus(_ text: String) {
        Task { @MainActor in
            self.status = text
            self.append(text)
        }
    }

    nonisolated func bleDidReadRemoteEid(_ eid: Data, peripheral: CBPeripheral) {
        Task { @MainActor in
            self.append("Remote EID \(self.hex(eid))")
            do {
                if let peer = try self.engine.resolve(beacon: eid, epoch: self.epoch) {
                    self.append("Resolved known peer \(self.hex(peer.bytes).prefix(16))…")
                    self.status = "Known peer nearby"
                } else {
                    self.append("Unknown EID — pairing if initiator")
                }
            } catch {
                self.append("resolve error: \(error)")
            }
            self.flushPendingOutbound()
        }
    }

    nonisolated func bleDidReceivePairingBytes(_ data: Data) {
        Task { @MainActor in
            guard let pairing = self.pairing else {
                self.append("Pairing bytes with no session")
                return
            }
            self.append("pairing recv \(data.count) bytes")
            let ev = pairing.read(message: data)
            self.apply(ev)
        }
    }
}
