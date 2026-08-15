import CoreBluetooth
import Foundation

/// GATT layout for the iOS reference sample.
///
/// iOS apps cannot set arbitrary legacy Advertising Data (the 15-byte layout
/// from `engytita-ble`). This demo broadcasts the 8-byte EID as a readable
/// GATT characteristic under a fixed service UUID instead.
enum EngytitaBleIds {
    /// Bluetooth base UUID for 16-bit `0xE671` (provisional Engytita service).
    static let service = CBUUID(string: "0000E671-0000-1000-8000-00805F9B34FB")
    static let eid = CBUUID(string: "0000E672-0000-1000-8000-00805F9B34FB")
    /// Central writes pairing ciphertext here (responder inbox / initiator→responder).
    static let pairingWrite = CBUUID(string: "0000E673-0000-1000-8000-00805F9B34FB")
    /// Peripheral notifies pairing ciphertext here (responses to central).
    static let pairingNotify = CBUUID(string: "0000E674-0000-1000-8000-00805F9B34FB")
}

protocol BleStackDelegate: AnyObject {
    func bleDidUpdateStatus(_ text: String)
    func bleDidReadRemoteEid(_ eid: Data, peripheral: CBPeripheral)
    func bleDidReceivePairingBytes(_ data: Data)
}

/// Dual-role BLE: advertise+GATT server (responder / beacon) and scan+GATT client (initiator).
final class BleStack: NSObject {
    weak var delegate: BleStackDelegate?

    private var peripheralManager: CBPeripheralManager!
    private var centralManager: CBCentralManager!

    private var eidCharacteristic: CBMutableCharacteristic?
    private var pairingWriteCharacteristic: CBMutableCharacteristic?
    private var pairingNotifyCharacteristic: CBMutableCharacteristic?

    private(set) var connectedPeripheral: CBPeripheral?
    private var remotePairingWrite: CBCharacteristic?
    private var remotePairingNotify: CBCharacteristic?
    private var remoteEidChar: CBCharacteristic?

    private var localEid: Data = Data(repeating: 0, count: 8)

    override init() {
        super.init()
        peripheralManager = CBPeripheralManager(delegate: self, queue: .main)
        centralManager = CBCentralManager(delegate: self, queue: .main)
    }

    func setLocalEid(_ eid: Data) {
        precondition(eid.count == 8)
        localEid = eid
        eidCharacteristic?.value = eid
        // Restart advertising payload is service-UUID only; EID lives on the characteristic.
        if peripheralManager.state == .poweredOn {
            startAdvertising()
        }
    }

    func startAdvertising() {
        guard peripheralManager.state == .poweredOn else { return }
        if peripheralManager.isAdvertising {
            peripheralManager.stopAdvertising()
        }
        setupServiceIfNeeded()
        peripheralManager.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [EngytitaBleIds.service],
            CBAdvertisementDataLocalNameKey: "Engytita",
        ])
        delegate?.bleDidUpdateStatus("Advertising Engytita GATT service")
    }

    func stopAdvertising() {
        peripheralManager.stopAdvertising()
    }

    func startScanning() {
        guard centralManager.state == .poweredOn else { return }
        centralManager.scanForPeripherals(
            withServices: [EngytitaBleIds.service],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
        delegate?.bleDidUpdateStatus("Scanning for Engytita peers…")
    }

    func stopScanning() {
        centralManager.stopScan()
    }

    func connect(_ peripheral: CBPeripheral) {
        stopScanning()
        connectedPeripheral = peripheral
        peripheral.delegate = self
        centralManager.connect(peripheral, options: nil)
    }

    /// Write pairing bytes to the connected peer (central → peripheral).
    func writePairingBytes(_ data: Data) {
        guard let peripheral = connectedPeripheral, let ch = remotePairingWrite else {
            delegate?.bleDidUpdateStatus("No pairing write characteristic")
            return
        }
        peripheral.writeValue(data, for: ch, type: .withResponse)
    }

    /// Notify pairing bytes to the connected central (peripheral → central).
    func notifyPairingBytes(_ data: Data) {
        guard let ch = pairingNotifyCharacteristic else { return }
        peripheralManager.updateValue(data, for: ch, onSubscribedCentrals: nil)
    }

    private func setupServiceIfNeeded() {
        guard eidCharacteristic == nil else {
            eidCharacteristic?.value = localEid
            return
        }
        let eid = CBMutableCharacteristic(
            type: EngytitaBleIds.eid,
            properties: [.read, .notify],
            value: nil,
            permissions: [.readable]
        )
        eid.value = localEid
        let pairingWrite = CBMutableCharacteristic(
            type: EngytitaBleIds.pairingWrite,
            properties: [.write],
            value: nil,
            permissions: [.writeable]
        )
        let pairingNotify = CBMutableCharacteristic(
            type: EngytitaBleIds.pairingNotify,
            properties: [.notify, .read],
            value: nil,
            permissions: [.readable]
        )
        eidCharacteristic = eid
        pairingWriteCharacteristic = pairingWrite
        pairingNotifyCharacteristic = pairingNotify

        let service = CBMutableService(type: EngytitaBleIds.service, primary: true)
        service.characteristics = [eid, pairingWrite, pairingNotify]
        peripheralManager.add(service)
    }
}

extension BleStack: CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        if peripheral.state == .poweredOn {
            startAdvertising()
        } else {
            delegate?.bleDidUpdateStatus("Peripheral BLE state: \(peripheral.state.rawValue)")
        }
    }

    func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didReceiveRead request: CBATTRequest
    ) {
        if request.characteristic.uuid == EngytitaBleIds.eid {
            guard request.offset <= localEid.count else {
                peripheral.respond(to: request, withResult: .invalidOffset)
                return
            }
            request.value = localEid.subdata(in: request.offset..<localEid.count)
            peripheral.respond(to: request, withResult: .success)
            return
        }
        peripheral.respond(to: request, withResult: .requestNotSupported)
    }

    func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didReceiveWrite requests: [CBATTRequest]
    ) {
        for request in requests {
            if request.characteristic.uuid == EngytitaBleIds.pairingWrite, let value = request.value {
                delegate?.bleDidReceivePairingBytes(value)
            }
        }
        peripheral.respond(to: requests[0], withResult: .success)
    }
}

extension BleStack: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state != .poweredOn {
            delegate?.bleDidUpdateStatus("Central BLE state: \(central.state.rawValue)")
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        delegate?.bleDidUpdateStatus(
            "Found \(peripheral.name ?? "peer") rssi=\(RSSI) — tap Connect in UI if listed"
        )
        // Surface via notification-style callback using a synthetic path: store last peripheral
        NotificationCenter.default.post(
            name: .engytitaDidDiscoverPeer,
            object: peripheral,
            userInfo: ["rssi": RSSI]
        )
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        delegate?.bleDidUpdateStatus("Connected — discovering services")
        peripheral.discoverServices([EngytitaBleIds.service])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        delegate?.bleDidUpdateStatus("Connect failed: \(error?.localizedDescription ?? "?")")
    }
}

extension BleStack: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let services = peripheral.services else { return }
        for service in services where service.uuid == EngytitaBleIds.service {
            peripheral.discoverCharacteristics(
                [EngytitaBleIds.eid, EngytitaBleIds.pairingWrite, EngytitaBleIds.pairingNotify],
                for: service
            )
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let chars = service.characteristics else { return }
        for ch in chars {
            switch ch.uuid {
            case EngytitaBleIds.eid:
                remoteEidChar = ch
                peripheral.readValue(for: ch)
            case EngytitaBleIds.pairingWrite:
                remotePairingWrite = ch
            case EngytitaBleIds.pairingNotify:
                remotePairingNotify = ch
                peripheral.setNotifyValue(true, for: ch)
            default:
                break
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard let value = characteristic.value else { return }
        if characteristic.uuid == EngytitaBleIds.eid {
            delegate?.bleDidReadRemoteEid(value, peripheral: peripheral)
        } else if characteristic.uuid == EngytitaBleIds.pairingNotify {
            delegate?.bleDidReceivePairingBytes(value)
        }
    }
}

extension Notification.Name {
    static let engytitaDidDiscoverPeer = Notification.Name("engytitaDidDiscoverPeer")
}
