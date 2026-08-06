# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**詳細については以下を確認してください:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF formatは、その複雑さとデータを隠蔽できる可能性で知られており、CTF forensics challengeの主要な対象となっています。PDFは、圧縮または暗号化されている可能性のあるプレーンテキスト要素とバイナリオブジェクトを組み合わせており、JavaScriptやFlashなどの言語によるスクリプトを含めることもできます。PDFの構造を理解するには、Didier Stevensの[入門資料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)を参照するか、テキストエディタやOrigamiなどのPDF専用エディタを使用できます。

PDFを詳細に調査または操作するには、[qpdf](https://github.com/qpdf/qpdf)や[Origami](https://github.com/mobmewireless/origami-pdf)などのツールを利用できます。PDF内のHidden dataは、以下の場所に隠されている可能性があります。

- 非表示レイヤー
- AdobeによるXMP metadata format
- Incremental generations
- 背景と同じ色のテキスト
- 画像の背後にあるテキストまたは重なった画像
- 表示されないコメント

Custom PDF analysisには、[PeepDF](https://github.com/jesparza/peepdf)などのPython librariesを使用して、専用のparsing scriptsを作成できます。さらに、PDFはHidden dataを保存できる可能性が非常に広いため、PDFのリスクとcountermeasuresに関するNSA guideは、元の場所では現在ホストされていないものの、今でも有益な知見を提供しています。[このguideのコピー](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)や、Ange Albertiniによる[PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)のcollectionから、さらに詳しく学ぶことができます。<sup>[[4]](#references)[[5]](#references)</sup>

## Common Malicious Constructs

攻撃者は、documentが開かれたときや操作されたときに自動的に実行される特定のPDF objectsやactionsを悪用することがよくあります。調査すべきkeywordは以下のとおりです。

* **/OpenAction, /AA** – open時または特定のevent時に実行されるautomatic actions。
* **/JS, /JavaScript** – embedded JavaScript（多くの場合、obfuscatedされているか、複数のobjectsに分割されている）。
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers。
* **/RichMedia, /Flash, /3D** – payloadsを隠す可能性のあるmultimedia objects。
* **/EmbeddedFile /Filespec** – file attachments（EXE、DLL、OLEなど）。
* **/ObjStm, /XFA, /AcroForm** – shell-codeを隠すために悪用されることが多いobject streamsまたはforms。
* **Incremental updates** – 複数の%%EOF markers、または非常に大きな**/Prev** offsetは、AVを回避するためにsigning後にdataが追加されたことを示している可能性があります。

前述のtokenのいずれかが、suspicious strings（powershell、cmd.exe、calc.exe、base64など）とともに現れる場合、そのPDFはより詳細なanalysisに値します。

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
Additional useful projects (actively maintained 2023-2025):
* **pdfcpu** – *lint*、*decrypt*、*extract*、*compress*、*sanitize* が可能な Go library/CLI。
* **pdf-inspector** – object graph と streams を render する browser-based visualizer。
* **PyMuPDF (fitz)** – hardened sandbox 内で embedded JS を安全に detonate するため、ページを画像に render できる scriptable Python engine。

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC は、threat actors が VBA macros を含む MHT-based Word document を最終 **%%EOF** の後に追加し、valid PDF と valid DOC の両方として扱える file を作成していたことを確認した。PDF layer だけを parse する AV engines は macro を見逃す。Static PDF keywords はクリーンだが、`file` は依然として `%PDF` と表示する。文字列 `<w:WordDocument>` も含む PDF は、極めて suspicious なものとして扱う。<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries は incremental update feature を悪用して、benign な最初の revision に署名を保持したまま、malicious な `/OpenAction` を持つ 2 つ目の **/Catalog** を挿入する。最初の xref table だけを inspect する tools は bypass される。
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – embedded CIDType2 fonts から vulnerable な **CoolType.dll** function に到達でき、crafted document が開かれると、user の privileges で remote code execution が可能になる。APSB24-29、2024 年 5 月に patch 済み。<sup>[[3]](#references)</sup>

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

1. **迅速にパッチを適用する** – Acrobat/Reader を最新の Continuous track に保ちます。実際の攻撃で確認されている RCE chain の多くは、数か月前に修正された n-day vulnerability を悪用しています。
2. **gateway で active content を除去する** – `pdfcpu sanitize` または `qpdf --qdf --remove-unreferenced` を使用して、受信した PDF から JavaScript、embedded files、launch actions を削除します。
3. **Content Disarm & Reconstruction (CDR)** – sandbox host 上で PDF を画像（または PDF/A）に変換し、active objects を破棄しながら視覚的な忠実度を維持します。
4. **ほとんど使用されない機能をブロックする** – Reader の enterprise 向け「Enhanced Security」設定では、JavaScript、multimedia、3D rendering を無効化できます。
5. **ユーザー教育** – social engineering（invoice や resume を使った lure）は依然として initial vector です。不審な添付ファイルを IR に転送するよう従業員に教育します。

## 参考資料

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – PDF file に malicious Word file を埋め込むことによる Detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat and Reader 向け security update available (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - guide の copy](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
