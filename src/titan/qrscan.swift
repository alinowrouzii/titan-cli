import AppKit
import Foundation
import Vision

let path = CommandLine.arguments[1]
let url = URL(fileURLWithPath: path)
guard let image = NSImage(contentsOf: url) else {
    fputs("could not open image\n", stderr)
    exit(2)
}
var rect = CGRect(origin: .zero, size: image.size)
guard let cg = image.cgImage(forProposedRect: &rect, context: nil, hints: nil) else {
    fputs("could not read image\n", stderr)
    exit(2)
}
let request = VNDetectBarcodesRequest()
request.symbologies = [.qr]
let handler = VNImageRequestHandler(cgImage: cg, options: [:])
do {
    try handler.perform([request])
} catch {
    fputs("\(error)\n", stderr)
    exit(2)
}
let lines = (request.results ?? []).compactMap { $0.payloadStringValue }
if lines.isEmpty {
    fputs("no QR code\n", stderr)
    exit(3)
}
for line in lines {
    print(line)
}
