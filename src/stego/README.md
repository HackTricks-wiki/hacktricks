# Stego

{{#include ../banners/hacktricks-training.md}}

このセクションは、ファイル (images/audio/video/documents/archives) およびテキストベースの steganography からの **隠されたデータの発見と抽出** に焦点を当てています。

暗号攻撃が目的の場合は、**Crypto** セクションへ移動してください。

## Entry Point

steganography をフォレンジックの問題として扱ってください：実際のコンテナを特定し、重要な箇所（metadata、appended data、embedded files）を列挙してから、コンテンツレベルの抽出技術を適用します。

### Workflow & triage

container identification、metadata/string inspection、carving、および format-specific branching を優先する構造化されたワークフロー。
{{#ref}}
workflow/README.md
{{#endref}}

### 画像

大半の CTF stego が存在する領域：LSB/bit-planes (PNG/BMP)、chunk/file-format weirdness、JPEG tooling、および multi-frame GIF tricks。
{{#ref}}
images/README.md
{{#endref}}

### 音声

スペクトログラムによるメッセージ、sample LSB embedding、および telephone keypad tones (DTMF) が繰り返し見られるパターンです。
{{#ref}}
audio/README.md
{{#endref}}

### テキスト

テキストが通常通り表示されるが挙動が不自然な場合は、Unicode homoglyphs、zero-width characters、または whitespace-based encoding を検討してください。
{{#ref}}
text/README.md
{{#endref}}

### ドキュメント

PDFs および Office ファイルはまずコンテナです。攻撃は通常、embedded files/streams、object/relationship graphs、および ZIP extraction を中心に展開します。
{{#ref}}
documents/README.md
{{#endref}}

### Malware と配信スタイルの steganography

Payload の配信では、ピクセルレベルの隠蔽ではなく、marker-delimited text payloads を載せた見た目が正当なファイル（例: GIF/PNG）が頻繁に使われます。
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
