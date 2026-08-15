import CoreBluetooth
import SwiftUI

struct ContentView: View {
    @State private var model = DemoModel()

    var body: some View {
        NavigationStack {
            List {
                Section("This device") {
                    LabeledContent("Peer id") { Text(model.peerIdHex.prefix(16) + "…").font(.caption.monospaced()) }
                    LabeledContent("Epoch") { Text("\(model.epoch)") }
                    LabeledContent("EID") { Text(model.localEidHex).font(.caption.monospaced()) }
                    Button("Refresh beacon (epoch)") { model.refreshBeacon() }
                }

                Section("Role") {
                    Button("Advertise as responder (wait to be paired)") {
                        model.startAsResponder()
                    }
                    Button("Scan as initiator") {
                        model.startScanAsInitiator()
                    }
                    Text(model.status)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                if !model.discovered.isEmpty {
                    Section("Discovered") {
                        ForEach(model.discovered, id: \.id) { item in
                            Button("Connect & pair: \(item.name)") {
                                model.connectAndPair(item.peripheral)
                            }
                        }
                    }
                }

                if let sas = model.sasPrompt {
                    Section("SAS") {
                        Text("Compare out-of-band, then type the digits you heard/saw.")
                        Text("Displayed: \(sas)")
                            .font(.title2.monospaced())
                        TextField("Type 6 digits", text: $model.sasEntry)
                            .keyboardType(.numberPad)
                            .textInputAutocapitalization(.never)
                        Button("Confirm SAS") { model.confirmSas() }
                        Button("Reject SAS", role: .destructive) { model.rejectSas() }
                    }
                }

                Section("Session") {
                    Text(model.keysDerived ? "Keys derived ✓ (STS 16 + transport 32; not shown)" : "No session keys yet")
                }

                Section("Notes") {
                    Text(
                        "iOS cannot emit engytita-ble legacy AD bytes from an app. This reference sample puts the EID on a GATT characteristic under UUID 0xE671. Nearby Interaction ranging is untrusted / not keyed by Engytita."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Section("Log") {
                    ForEach(Array(model.log.enumerated()), id: \.offset) { _, line in
                        Text(line).font(.caption2.monospaced())
                    }
                }
            }
            .navigationTitle("Engytita Demo")
        }
    }
}
