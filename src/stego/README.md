# Stego

{{#include ../banners/hacktricks-training.md}}

このセクションでは、ファイル（画像/音声/動画/ドキュメント/アーカイブ）およびテキストベースのsteganographyから**hidden dataを見つけて抽出する**方法に焦点を当てます。

cryptographic attacksを探している場合は、**Crypto**セクションに移動してください。

## Entry Point

steganographyにはforensicsの問題として取り組みます。実際のcontainerを特定し、signalの強い場所（metadata、追加データ、embedded files）を列挙してから、content-level extraction techniquesを適用します。

### Workflow & triage

container identification、metadata/string inspection、carving、format-specific branchingを優先する、構造化されたworkflowです。

{{#ref}}
workflow/README.md
{{#endref}}

### Images

CTF stegoの大部分が存在する場所です。LSB/bit-planes（PNG/BMP）、chunk/file-formatの奇妙な挙動、JPEG tooling、multi-frame GIF tricksなどを扱います。

{{#ref}}
images/README.md
{{#endref}}

### Audio

Spectrogram messages、sample LSB embedding、telephone keypad tones（DTMF）は、繰り返し登場するパターンです。

{{#ref}}
audio/README.md
{{#endref}}

### Text

テキストが通常どおり表示されるにもかかわらず予期しない挙動をする場合は、Unicode homoglyphs、zero-width characters、またはwhitespace-based encodingを検討してください。

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFsとOffice filesはまずcontainerです。attacksは通常、embedded files/streams、object/relationship graphs、ZIP extractionを中心に行われます。

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Payload deliveryでは、pixel-level hidingではなく、marker-delimited text payloadsを含む、一見有効なファイル（例：GIF/PNG）が頻繁に使用されます。

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
