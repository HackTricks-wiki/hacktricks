# PDFファイル分析

{{#include ../../../banners/hacktricks-training.md}}

**詳細については、こちらを確認してください:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)。<sup>[[1]](#references)</sup>

PDF形式は、その複雑さとデータを隠蔽できる可能性で知られており、CTF forensics challengeの中心的な対象となっています。プレーンテキスト要素とバイナリオブジェクトが組み合わされており、それらは圧縮または暗号化されている場合があります。また、JavaScriptやFlashなどの言語によるスクリプトを含めることもできます。PDFの構造を理解するには、Didier Stevensの[入門資料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)を参照するか、テキストエディタやOrigamiのようなPDF専用エディタを使用できます。

PDFを詳しく調査または操作するには、[qpdf](https://github.com/qpdf/qpdf)や[Origami](https://github.com/mobmewireless/origami-pdf)などのツールを利用できます。PDF内のhidden dataは、次の場所に隠されている可能性があります。

- 非表示レイヤー
- AdobeのXMP metadata形式
- Incremental generations
- 背景と同じ色のテキスト
- 画像の背後にあるテキスト、または重なり合った画像
- 表示されないコメント

PDFを独自に分析する場合は、[PeepDF](https://github.com/jesparza/peepdf)のようなPython libraryを使用して、独自のparsing scriptを作成できます。さらに、PDFはhidden dataの保存先として非常に広範な可能性を持つため、PDFのリスクとcountermeasuresに関するNSA guideは、元の場所ではホストされなくなったものの、今でも有益な知見を提供しています。[ガイドのコピー](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)や、Ange Albertiniによる[PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)のコレクションから、さらに詳しく学ぶことができます。<sup>[[4]](#references)[[5]](#references)</sup>

## Common Malicious Constructs

Attackersは、documentが開かれたときや操作されたときに自動的に実行される、特定のPDF objectやactionを悪用することがよくあります。調査対象として重要なkeywordは次のとおりです。

* **/OpenAction, /AA** – open時、または特定のevent時に実行されるautomatic action。
* **/JS, /JavaScript** – embedded JavaScript（多くの場合、難読化されているか、複数のobjectに分割されています）。
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launcher。
* **/RichMedia, /Flash, /3D** – payloadを隠せるmultimedia object。
* **/EmbeddedFile /Filespec** – file attachment（EXE、DLL、OLEなど）。
* **/ObjStm, /XFA, /AcroForm** – shell-codeを隠すために悪用されることが多いobject streamまたはform。
* **Incremental updates** – 複数の%%EOF marker、または非常に大きな**/Prev** offsetは、AVを回避するために署名後にdataが追加されたことを示している可能性があります。

前述のtokenがpowershell、cmd.exe、calc.exe、base64などの不審なstringとともに現れる場合、そのPDFはより詳細な分析に値します。

---

## Static analysis cheat-sheet

以下の例では、document化された`pdf-parser.py`、qpdf、pdfcpuのcommand-line interfaceを使用します。<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
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
追加の有用なプロジェクト（2023〜2025年に積極的にメンテナンス）:
* **pdfcpu** – PDFの検証、復号、抽出、最適化、操作が可能なGoライブラリ/CLI。<sup>[[9]](#references)</sup>
* **pdf-inspector** – オブジェクトグラフとストリームをレンダリングするブラウザベースのビジュアライザー。
* **PyMuPDF** – PDFの検査やページのラスタ画像へのレンダリングに使用できる、scriptableなPythonバインディング。parser/rendererは信頼できないファイルの攻撃対象領域として扱い、適切に隔離されたanalysis environment内で実行すること。<sup>[[8]](#references)</sup>

---

## 最近の攻撃手法（2023〜2025年）

* **MalDoc in PDF polyglot (2023)** – JPCERT/CCは、Wordで作成したVBA macro付きのMHTファイルをPDFに追加し、PDF magicを維持しながらWordでも開けるようにするtechniqueを報告した。PDF専用のanalysis tools、sandboxes、またはantivirusは、Wordとして開いたときに悪意のある動作が発生するため、macroを見逃す可能性がある。ほかのMHT indicatorsとともに`<w:WordDocument>` markerを探すこと。<sup>[[2]](#references)</sup>
* **署名済みPDFに対するShadow attacks** – attackersは、PDFが署名される前にhidden contentを配置し、その後、catalogまたはobject referencesを変更するincremental updateを追加できる。これにより、元のsignatureが有効なまま、viewersにhidden contentを表示させられる。このtechniqueは、このようなupdatesをharmlessと分類するviewersを回避できる可能性がある。<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobeは、このcritical vulnerabilityを、arbitrary code executionにつながる可能性があるuse-after-freeと評価している。APSB24-29は2024年5月14日に公開された。<sup>[[3]](#references)</sup>

---

## YARA quick rule template
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

1. **迅速にパッチを適用する** – Acrobat/Reader を最新の Continuous track に保ちます。実際の攻撃で確認されている RCE chain の多くは、数か月前に修正された n-day vulnerabilities を悪用しています。
2. **gateway で active content を除去する** – JavaScript、embedded files、launch actions、forms、multimedia を明示的に除去する、専用かつポリシー管理された sanitizer または CDR product を使用します。`qpdf --qdf` を使うと PDF objects の inspection が容易になり、pdfcpu は validation と manipulation の機能を提供します。ただし、どちらの command も単独では active content が除去されたことの証明にはなりません。<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – sandbox host 上で PDF を images（または PDF/A）に変換し、active objects を破棄しながら visual fidelity を維持します。
4. **ほとんど使用されない機能を block する** – Reader の enterprise 向け「Enhanced Security」settings では、JavaScript、multimedia、3D rendering を無効化できます。
5. **ユーザー教育** – social engineering（invoice および resume の lure）は依然として initial vector です。不審な attachments は IR に forward するよう従業員に教育します。

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – 悪意のある Word ファイルを PDF ファイルに埋め込むことによる Detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat and Reader で利用可能になった Security update (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - guide の copy](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Signed PDFs における Content の Hiding and Replacing](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf command-line options](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
