# PDF File analysis

**詳細については、こちらを確認してください:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF format は複雑で、データを隠蔽できる可能性があることで知られており、CTF forensics challenge の主要な対象となっています。PDF はプレーンテキスト要素と binary object を組み合わせており、それらは圧縮または暗号化されている場合があります。また、JavaScript や Flash などの言語による script を含めることもできます。PDF の構造を理解するには、Didier Stevens の[入門資料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)を参照するか、text editor や Origami などの PDF 専用 editor を使用できます。

PDF を詳細に調査または操作するには、[qpdf](https://github.com/qpdf/qpdf) や [Origami](https://github.com/mobmewireless/origami-pdf) などの tool を利用できます。PDF 内の hidden data は、以下の場所に隠されている可能性があります。

- 非表示の layer
- Adobe の XMP metadata format
- Incremental generation
- 背景と同じ色の text
- image の背後にある text または重なり合った image
- 表示されない comment

カスタム PDF analysis には、[PeepDF](https://github.com/jesparza/peepdf) などの Python library を使用して、専用の parsing script を作成できます。さらに、PDF は hidden data の保存場所として非常に大きな可能性を持つため、現在は元の場所でホストされていないものの、PDF のリスクと countermeasure に関する NSA guide などの resource も、依然として有益な知見を提供します。[guide の copy](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) と、Ange Albertini による [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) の collection は、この विषयについてさらに学ぶための資料になります。<sup>[[4]](#references)[[5]](#references)</sup>

## Common Malicious Constructs

Attackers は、document を開いたときや操作したときに自動実行される特定の PDF object や action を悪用することがよくあります。以下の keyword を探す価値があります。

* **/OpenAction, /AA** – open 時、または特定の event 発生時に実行される automatic action。
* **/JS, /JavaScript** – embedded JavaScript（多くの場合、obfuscate されているか、複数の object に分割されています）。
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launcher。
* **/RichMedia, /Flash, /3D** – payload を隠す可能性のある multimedia object。
* **/EmbeddedFile /Filespec** – file attachment（EXE、DLL、OLE など）。
* **/ObjStm, /XFA, /AcroForm** – shell-code を隠すために悪用されることが多い object stream または form。
* **Incremental update** – 複数の %%EOF marker や非常に大きな **/Prev** offset は、AV を回避するため、署名後に data が append されたことを示している可能性があります。

以前の token のいずれかが suspicious string（powershell、cmd.exe、calc.exe、base64 など）と組み合わさって現れる場合、その PDF はさらに詳しく分析する必要があります。

---

## Static analysis cheat-sheet

以下の例では、documented `pdf-parser.py`、qpdf、pdfcpu の command-line interface を使用します。<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
追加の有用なプロジェクト（2023-2025年に積極的にメンテナンス）:
* **pdfcpu** – PDFの検証、復号、抽出、最適化、操作が可能なGoライブラリ/CLI。<sup>[[9]](#references)</sup>
* **pdf-inspector** – オブジェクトグラフとストリームをレンダリングするブラウザベースのビジュアライザー。
* **PyMuPDF** – PDFの検査やページのラスター画像へのレンダリングが可能な、スクリプトで利用できるPython bindings。parser/rendererはuntrusted-file attack surfaceとして扱い、適切に分離されたanalysis environment内で実行してください。<sup>[[8]](#references)</sup>

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CCは、Wordで作成したVBA macros付きのMHT fileをPDFに追加し、PDF magicを維持しながらWordでも開けるようにするtechniqueを報告しました。PDF-only analysis tools、sandboxes、またはantivirusでは、Wordとして開かれたときに悪意のある動作が発生するため、macroを見逃す可能性があります。他のMHT indicatorsとともに`<w:WordDocument>` markerを探してください。<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – attackersは、PDFが署名される前にhidden contentを配置し、その後incremental updateを追加してcatalogまたはobject referencesを変更できます。これにより、original signatureが有効なまま、viewersにhidden contentを表示させられます。このtechniqueは、そのようなupdatesをharmlessと分類するviewersを回避できます。<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobeはこのcritical vulnerabilityを、arbitrary code executionにつながる可能性のあるuse-after-freeと評価しています。APSB24-29は2024年5月14日に公開されました。<sup>[[3]](#references)</sup>

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

1. **迅速に patch する** – Acrobat/Reader を最新の Continuous track に維持する。実際の攻撃で確認される RCE chain の多くは、数か月前に修正された n-day vulnerability を悪用している。
2. **gateway で active content を除去する** – JavaScript、埋め込みファイル、launch action、form、multimedia を明示的に削除する、専用の policy-controlled sanitizer または CDR product を使用する。`qpdf --qdf` を使うと PDF object を検査しやすくなる。一方、pdfcpu は validation および manipulation 機能を提供するが、どちらの command だけでも active content が除去された証明にはならない。<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – sandbox host 上で PDF を image（または PDF/A）に変換し、active object を破棄しながら見た目の忠実性を維持する。
4. **ほとんど使用されない機能を block する** – Reader の企業向け「Enhanced Security」設定では、JavaScript、multimedia、3D rendering を無効化できる。
5. **User education** – social engineering（invoice や resume の lure）は依然として initial vector である。不審な attachment を IR に転送するよう従業員に教育する。

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – PDF ファイルに悪意のある Word ファイルを埋め込むことによる Detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat および Reader の Security update available (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - guide の copy](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Signed PDF における Content の Hiding と Replacing](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf command-line options](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
