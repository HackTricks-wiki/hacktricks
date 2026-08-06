# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**詳細については以下を確認してください:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF formatは、その複雑さとデータを隠蔽できる可能性で知られており、CTF forensics challengeの主要な対象となっています。PDFはプレーンテキスト要素とバイナリオブジェクトを組み合わせており、それらは圧縮または暗号化されている場合があります。また、JavaScriptやFlashなどの言語によるスクリプトを含めることもできます。PDFの構造を理解するには、Didier Stevensの[入門資料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)を参照するか、テキストエディタやOrigamiのようなPDF専用エディタを使用できます。

PDFを詳しく調査または操作するには、[qpdf](https://github.com/qpdf/qpdf)や[Origami](https://github.com/mobmewireless/origami-pdf)などのツールを利用できます。PDF内のHidden dataは、以下の場所に隠されている可能性があります。

- 非表示レイヤー
- AdobeのXMP metadata format
- Incremental generations
- 背景と同じ色のテキスト
- 画像の背後にあるテキスト、または重なり合った画像
- 表示されないコメント

カスタムPDF分析には、[PeepDF](https://github.com/jesparza/peepdf)などのPython librariesを使用して、目的に合わせたparsing scriptを作成できます。さらに、PDFはHidden dataを保存できる可能性が非常に高いため、PDFのrisksとcountermeasuresに関するNSA guideは、元の場所では現在ホストされていないものの、依然として有益な情報を提供しています。[guideのcopy](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)や、Ange Albertiniによる[PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)のcollectionから、さらに詳しく学ぶことができます。

## Common Malicious Constructs

Attackersは、documentを開いたときや操作したときに自動的に実行される特定のPDF objectsやactionsを悪用することがよくあります。以下のkeywordsを探してください。

* **/OpenAction, /AA** – open時または特定のevents発生時に実行されるautomatic actions。
* **/JS, /JavaScript** – embedded JavaScript（多くの場合、obfuscatedまたは複数のobjectsに分割されている）。
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers。
* **/RichMedia, /Flash, /3D** – payloadsを隠す可能性があるmultimedia objects。
* **/EmbeddedFile /Filespec** – file attachments（EXE、DLL、OLEなど）。
* **/ObjStm, /XFA, /AcroForm** – shell-codeを隠すために悪用されることが多いobject streamsまたはforms。
* **Incremental updates** – 複数の%%EOF markersまたは非常に大きな**/Prev** offsetは、AVを回避するためにsigning後にdataがappendされたことを示している可能性があります。

前述のtokensがsuspicious strings（powershell、cmd.exe、calc.exe、base64など）とともに現れる場合、そのPDFはより詳細な分析に値します。

---

## Static analysis cheat-sheet
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
追加の有用な project（2023-2025 年に actively maintained）:
* **pdfcpu** – PDF の *lint*、*decrypt*、*extract*、*compress*、*sanitize* が可能な Go library/CLI。
* **pdf-inspector** – object graph と streams を render する browser-based visualizer。
* **PyMuPDF (fitz)** – hardened sandbox 内で埋め込み JS を安全に実行し、pages を images として render できる scriptable Python engine。

---

## Recent attack techniques (2023-2025）

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC は、threat actors が MHT-based Word document with VBA macros を最後の **%%EOF** の後に追加し、valid PDF と valid DOC の両方として扱える file を作成していたことを確認した。PDF layer のみを parse する AV engines は macro を見逃す。Static PDF keywords は clean だが、`file` は依然として `%PDF` を出力する。文字列 `<w:WordDocument>` も含む PDF は、非常に suspicious なものとして扱うべきである。<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries は incremental update feature を悪用し、benign な最初の revision を signed のまま維持しつつ、malicious な `/OpenAction` を持つ 2 つ目の **/Catalog** を挿入する。最初の xref table のみを inspect する tools は bypass される。
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – 脆弱な **CoolType.dll** function は embedded CIDType2 fonts から到達可能であり、crafted document が開かれると、user の privileges で remote code execution が可能になる。APSB24-29（2024 年 5 月）で patched。<sup>[[3]](#references)</sup>

---

## YARA クイックルールテンプレート
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

1. **迅速にパッチを適用する** – Acrobat/Reader を最新の Continuous track に保ちます。実際の攻撃で確認された RCE chain の大半は、数カ月前に修正された n-day vulnerabilities を悪用しています。
2. **gateway で active content を除去する** – `pdfcpu sanitize` または `qpdf --qdf --remove-unreferenced` を使用し、受信 PDF から JavaScript、embedded files、launch actions を削除します。
3. **Content Disarm & Reconstruction (CDR)** – sandbox host 上で PDF を画像（または PDF/A）に変換し、視覚的な忠実度を維持しながら active objects を破棄します。
4. **使用頻度の低い機能をブロックする** – Reader の企業向け「Enhanced Security」設定では、JavaScript、multimedia、3D rendering を無効化できます。
5. **ユーザー教育** – social engineering（請求書や履歴書を装った lure）は依然として initial vector です。不審な添付ファイルを IR に転送するよう従業員に指導します。

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
