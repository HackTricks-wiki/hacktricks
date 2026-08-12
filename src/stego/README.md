# Stego

{{#include ../banners/hacktricks-training.md}}

このセクションでは、画像、音声、動画、ドキュメント、アーカイブ、テキストから**隠されたデータを発見・抽出する方法**に焦点を当てます。Steganography は、あるデータの中に別のデータを埋め込むことで、通信の存在そのものを隠します。<sup>[[1]](#references)</sup>

暗号攻撃を探している場合は、**Crypto**セクションに移動してください。

## エントリーポイント

Steganography はフォレンジックの問題としてアプローチします。実際のコンテナを特定し、シグナルの強い場所（メタデータ、追加データ、埋め込みファイル）を列挙してから、コンテンツレベルの抽出技法を適用します。

### ワークフローとトリアージ

コンテナの特定、メタデータや文字列の検査、carving、フォーマット固有の分岐を優先する、体系的なワークフローです。

{{#ref}}
workflow/README.md
{{#endref}}

### 画像

CTF stego の多くが存在する分野です。LSB/bit-planes（PNG/BMP）、chunk/file-format の奇妙な挙動、JPEG tooling、multi-frame GIF のトリックなどを扱います。

{{#ref}}
images/README.md
{{#endref}}

### 音声

Spectrogram メッセージ、sample LSB embedding、telephone keypad tones（DTMF）は、繰り返し登場するパターンです。

{{#ref}}
audio/README.md
{{#endref}}

### テキスト

テキストが通常どおり表示されるにもかかわらず予期しない挙動を示す場合は、Unicode homoglyphs、zero-width characters、または whitespace-based encoding を検討します。

{{#ref}}
text/README.md
{{#endref}}

### ドキュメント

PDF と Office ファイルは、まずコンテナとして捉えます。攻撃は通常、埋め込みファイル/stream、object/relationship graph、ZIP extraction を中心に展開されます。

{{#ref}}
documents/README.md
{{#endref}}

### Malware と delivery-style steganography

Payload delivery では、GIF や PNG 画像などの一見有効なファイルを使用し、ピクセル内にデータを隠すのではなく、marker で区切られたテキスト payload を保持させることがあります。

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC 用語集 - Steganography](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
