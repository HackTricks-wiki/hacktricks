# Stego

{{#include ../banners/hacktricks-training.md}}

このセクションでは、画像、音声、動画、ドキュメント、アーカイブ、テキストから**隠されたデータを見つけて抽出する**方法に焦点を当てます。ステガノグラフィは、あるデータの中に別のデータを埋め込むことで、通信の存在を隠します。<sup>[[1]](#references)</sup>

暗号攻撃を調べている場合は、**Crypto**セクションに進んでください。

## Entry Point

ステガノグラフィはフォレンジックの問題として扱います。実際のコンテナを特定し、情報量の多い場所（メタデータ、追記データ、埋め込みファイル）を網羅的に調べてから、コンテンツ固有の抽出手法を適用します。

### ワークフローとトリアージ

コンテナの特定、メタデータや文字列の確認、カービング、形式に応じた分岐を優先する体系的なワークフローです。

{{#ref}}
workflow/README.md
{{#endref}}

### 画像

CTFのステガノグラフィの多くが使われる分野です。LSB/ビットプレーン（PNG/BMP）、チャンクやファイル形式の不審な点、JPEG用ツール、複数フレームGIFのトリックを扱います。

{{#ref}}
images/README.md
{{#endref}}

### 音声

スペクトログラムのメッセージ、サンプルへのLSB埋め込み、電話のキーパッド音（DTMF）は、よく見られるパターンです。

{{#ref}}
audio/README.md
{{#endref}}

### テキスト

テキストが通常どおり表示されるのに予想外の挙動をする場合は、Unicodeホモグリフ、ゼロ幅文字、空白を使ったエンコーディングを検討してください。

{{#ref}}
text/README.md
{{#endref}}

### ドキュメント

PDFやOfficeファイルは、まずコンテナとして扱います。攻撃では通常、埋め込みファイルやストリーム、オブジェクトやリレーションシップのグラフ、ZIPの展開が関係します。

{{#ref}}
documents/README.md
{{#endref}}

### マルウェアと配信型ステガノグラフィ

ペイロードの配信には、GIFやPNG画像のような一見正当なファイルを使用し、ピクセルにデータを隠すのではなく、マーカーで区切ったテキストペイロードを格納することがあります。

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC用語集 - ステガノグラフィ](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
