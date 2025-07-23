# PDFファイル分析

{{#include ../../../banners/hacktricks-training.md}}

**詳細については、次を確認してください:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDFフォーマットは、その複雑さとデータを隠す可能性で知られており、CTFフォレンジックチャレンジの焦点となっています。これは、圧縮または暗号化される可能性のあるバイナリオブジェクトとプレーンテキスト要素を組み合わせており、JavaScriptやFlashなどの言語でのスクリプトを含むことがあります。PDFの構造を理解するには、Didier Stevensの[入門資料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)を参照するか、テキストエディタやOrigamiのようなPDF専用エディタを使用できます。

PDFの詳細な探索や操作には、[qpdf](https://github.com/qpdf/qpdf)や[Origami](https://github.com/mobmewireless/origami-pdf)のようなツールが利用可能です。PDF内の隠されたデータは以下に隠されている可能性があります：

- 見えないレイヤー
- AdobeによるXMPメタデータ形式
- 増分生成
- 背景と同じ色のテキスト
- 画像の背後にあるテキストや重なり合った画像
- 表示されないコメント

カスタムPDF分析には、[PeepDF](https://github.com/jesparza/peepdf)のようなPythonライブラリを使用して、特注のパーススクリプトを作成できます。さらに、PDFの隠されたデータストレージの可能性は非常に広範であり、NSAのPDFリスクと対策に関するガイドのようなリソースは、もはや元の場所にホストされていないものの、貴重な洞察を提供します。[ガイドのコピー](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%Bútmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)や、Ange Albertiniによる[PDFフォーマットのトリック](https://github.com/corkami/docs/blob/master/PDF/PDF.md)のコレクションは、このテーマに関するさらなる読み物を提供します。

## 一般的な悪意のある構造

攻撃者は、文書が開かれたり操作されたりする際に自動的に実行される特定のPDFオブジェクトやアクションを悪用することがよくあります。探す価値のあるキーワード：

* **/OpenAction, /AA** – 開くときや特定のイベントで実行される自動アクション。
* **/JS, /JavaScript** – 埋め込まれたJavaScript（しばしば難読化されているか、オブジェクト間で分割されている）。
* **/Launch, /SubmitForm, /URI, /GoToE** – 外部プロセス/URLランチャー。
* **/RichMedia, /Flash, /3D** – ペイロードを隠すことができるマルチメディアオブジェクト。
* **/EmbeddedFile /Filespec** – ファイル添付（EXE、DLL、OLEなど）。
* **/ObjStm, /XFA, /AcroForm** – シェルコードを隠すために一般的に悪用されるオブジェクトストリームまたはフォーム。
* **増分更新** – 複数の%%EOFマーカーや非常に大きな**/Prev**オフセットは、AVを回避するために署名後にデータが追加されたことを示す可能性があります。

前述のトークンが疑わしい文字列（powershell、cmd.exe、calc.exe、base64など）と一緒に現れる場合、PDFはより深い分析に値します。

---

## 静的分析チートシート
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – decompress/inspect the object tree
pdf-parser.py -f suspicious.pdf                # interactive
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```
追加の有用なプロジェクト（2023-2025年に積極的にメンテナンス）:
* **pdfcpu** – PDFを*lint*、*decrypt*、*extract*、*compress*、および*sanitize*できるGoライブラリ/CLI。
* **pdf-inspector** – オブジェクトグラフとストリームをレンダリングするブラウザベースのビジュアライザー。
* **PyMuPDF (fitz)** – 埋め込まれたJSをハードンされたサンドボックスで爆発させるために、安全にページを画像にレンダリングできるスクリプタブルPythonエンジン。

---

## 最近の攻撃技術 (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CCは、脅威アクターが最終の**%%EOF**の後にVBAマクロを持つMHTベースのWord文書を追加するのを観察し、PDFとしてもDOCとしても有効なファイルを生成しました。PDFレイヤーのみを解析するAVエンジンはマクロを見逃します。静的PDFキーワードはクリーンですが、`file`は依然として`%PDF`を印刷します。`<w:WordDocument>`という文字列を含むPDFは非常に疑わしいものとして扱ってください。
* **Shadow-incremental updates (2024)** – 敵は、悪意のある`/OpenAction`を持つ第二の**/Catalog**を挿入するために、増分更新機能を悪用し、無害な最初の改訂を署名されたままにします。最初のxrefテーブルのみを検査するツールはバイパスされます。
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – 脆弱な**CoolType.dll**関数は、埋め込まれたCIDType2フォントから到達可能であり、作成された文書が開かれると、ユーザーの権限でリモートコード実行を可能にします。2024年5月にAPSB24-29でパッチが適用されました。

---

## YARAクイックルールテンプレート
```yara
rule Suspicious_PDF_AutoExec {
meta:
description = "Generic detection of PDFs with auto-exec actions and JS"
author      = "HackTricks"
last_update = "2025-07-20"
strings:
$pdf_magic = { 25 50 44 46 }          // %PDF
$aa        = "/AA" ascii nocase
$openact   = "/OpenAction" ascii nocase
$js        = "/JS" ascii nocase
condition:
$pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```
---

## 防御のヒント

1. **迅速にパッチを適用** – Acrobat/Readerを最新のContinuousトラックに保つ; 実際に観察されたほとんどのRCEチェーンは、数ヶ月前に修正されたn日脆弱性を利用しています。
2. **ゲートウェイでアクティブコンテンツを削除** – `pdfcpu sanitize`または`qpdf --qdf --remove-unreferenced`を使用して、受信PDFからJavaScript、埋め込みファイル、起動アクションを削除します。
3. **コンテンツの無効化と再構築 (CDR)** – サンドボックスホスト上でPDFを画像（またはPDF/A）に変換し、アクティブオブジェクトを破棄しながら視覚的忠実度を保持します。
4. **あまり使用されない機能をブロック** – Readerの企業向け「強化セキュリティ」設定では、JavaScript、マルチメディア、3Dレンダリングを無効にすることができます。
5. **ユーザー教育** – ソーシャルエンジニアリング（請求書や履歴書の誘惑）は最初のベクトルのままです; 従業員に疑わしい添付ファイルをIRに転送するよう教えます。

## 参考文献

* JPCERT/CC – “MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file” (2023年8月)
* Adobe – AcrobatとReaderのセキュリティ更新 (APSB24-29, 2024年5月)


{{#include ../../../banners/hacktricks-training.md}}
