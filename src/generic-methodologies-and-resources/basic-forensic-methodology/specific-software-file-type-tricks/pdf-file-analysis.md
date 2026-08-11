# PDF 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

**자세한 내용은 다음을 확인하세요:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF format은 복잡성과 데이터를 숨길 수 있는 가능성으로 잘 알려져 있어 CTF forensics challenges의 주요 대상이 됩니다. PDF는 일반 텍스트 요소와 binary objects를 결합하며, 이러한 객체는 압축되거나 암호화될 수 있고 JavaScript 또는 Flash와 같은 언어로 작성된 scripts를 포함할 수도 있습니다. PDF structure를 이해하려면 Didier Stevens의 [introductory material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)을 참고하거나, text editor 또는 Origami와 같은 PDF-specific editor를 사용할 수 있습니다.

PDF를 심층적으로 탐색하거나 조작하려면 [qpdf](https://github.com/qpdf/qpdf) 및 [Origami](https://github.com/mobmewireless/origami-pdf)와 같은 tools를 사용할 수 있습니다. PDF 내부의 hidden data는 다음과 같은 위치에 숨겨질 수 있습니다:

- Invisible layers
- Adobe의 XMP metadata format
- Incremental generations
- 배경과 같은 색상의 Text
- Images 뒤에 있거나 서로 겹쳐진 Text
- 표시되지 않는 Comments

Custom PDF analysis에는 [PeepDF](https://github.com/jesparza/peepdf)와 같은 Python libraries를 사용해 맞춤형 parsing scripts를 작성할 수 있습니다. 또한 PDF는 hidden data를 저장할 가능성이 매우 크기 때문에, 더 이상 원래 위치에서 호스팅되지 않는 NSA의 PDF risks and countermeasures guide와 같은 resources도 여전히 유용한 정보를 제공합니다. [guide 사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)과 Ange Albertini이 작성한 [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) 모음에서 이 주제에 대해 더 자세히 알아볼 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

## 일반적인 악성 Constructs

Attackers는 문서가 열리거나 상호작용할 때 자동으로 실행되는 특정 PDF objects 및 actions를 자주 악용합니다. 다음 keywords를 찾아볼 가치가 있습니다:

* **/OpenAction, /AA** – 문서가 열릴 때 또는 특정 events에서 실행되는 automatic actions.
* **/JS, /JavaScript** – 내장된 JavaScript(대개 obfuscated되거나 여러 objects로 분할됨).
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers.
* **/RichMedia, /Flash, /3D** – payloads를 숨길 수 있는 multimedia objects.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE 등).
* **/ObjStm, /XFA, /AcroForm** – shell-code를 숨기는 데 흔히 악용되는 object streams 또는 forms.
* **Incremental updates** – 여러 개의 %%EOF markers 또는 매우 큰 **/Prev** offset은 AV를 우회하기 위해 signing 후 data가 추가되었음을 나타낼 수 있습니다.

앞의 tokens 중 하나라도 suspicious strings (powershell, cmd.exe, calc.exe, base64 등)와 함께 나타나면 해당 PDF를 더 심층적으로 분석해야 합니다.

---

## Static analysis cheat-sheet

아래 examples에서는 문서화된 `pdf-parser.py`, qpdf 및 pdfcpu command-line interfaces를 사용합니다.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
추가로 유용한 프로젝트(2023-2025년 현재 활발히 유지 관리됨):
* **pdfcpu** – PDF를 검증, 복호화, 추출, 최적화 및 조작할 수 있는 Go 라이브러리/CLI입니다.<sup>[[9]](#references)</sup>
* **pdf-inspector** – object graph와 streams를 렌더링하는 브라우저 기반 visualizer입니다.
* **PyMuPDF** – PDF를 검사하고 페이지를 raster images로 렌더링할 수 있는 scriptable Python bindings입니다. parser/renderer를 신뢰할 수 없는 파일을 처리하는 attack surface로 간주하고, 적절히 격리된 analysis environment 내부에서 실행하세요.<sup>[[8]](#references)</sup>

---

## 최근 attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC는 Word로 생성된 VBA macros가 포함된 MHT file을 PDF에 추가하여 PDF magic을 유지하면서 Word에서도 열리게 하는 technique을 보고했습니다. PDF-only analysis tools, sandboxes 또는 antivirus는 Word로 열 때 악성 동작이 발생하므로 macro를 놓칠 수 있습니다. 다른 MHT indicators와 함께 `<w:WordDocument>` marker를 확인하세요.<sup>[[2]](#references)</sup>
* **서명된 PDF에 대한 Shadow attacks** – attackers는 PDF가 서명되기 전에 hidden content를 배치한 다음, catalog 또는 object references를 변경하는 incremental update를 추가하여 viewers가 original signature를 유효한 상태로 유지하면서 hidden content를 표시하도록 할 수 있습니다. 이러한 update를 harmless한 것으로 분류하는 viewers를 이 technique으로 우회할 수 있습니다.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe는 이 critical vulnerability를 arbitrary code execution으로 이어질 수 있는 use-after-free로 평가했으며, APSB24-29는 2024년 5월 14일에 published되었습니다.<sup>[[3]](#references)</sup>

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

## 방어 팁

1. **신속하게 패치** – Acrobat/Reader를 최신 Continuous track으로 유지하세요. 실제 공격에서 관찰된 대부분의 RCE chain은 수개월 전에 수정된 n-day 취약점을 악용합니다.
2. **Gateway에서 active content 제거** – JavaScript, embedded files, launch actions, forms 및 multimedia를 명시적으로 제거하는, 목적에 맞게 설계되고 정책으로 제어되는 sanitizer 또는 CDR 제품을 사용하세요. `qpdf --qdf`를 사용하면 PDF objects를 더 쉽게 검사할 수 있으며, pdfcpu는 validation 및 manipulation 기능을 제공합니다. 하지만 어느 명령도 단독으로 active content가 제거되었다는 증거가 되지는 않습니다.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – 시각적 충실도를 유지하면서 active objects를 제거할 수 있도록 sandbox host에서 PDF를 images(또는 PDF/A)로 변환하세요.
4. **거의 사용되지 않는 기능 차단** – Reader의 enterprise “Enhanced Security” settings를 사용하면 JavaScript, multimedia 및 3D rendering을 비활성화할 수 있습니다.
5. **사용자 교육** – social engineering(invoice 및 resume lure)은 여전히 initial vector입니다. 의심스러운 attachments를 IR로 전달하도록 직원들에게 교육하세요.

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – PDF 파일에 악성 Word 파일을 삽입한 Detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat 및 Reader에 사용 가능한 Security update (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - guide 사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Signed PDFs에서 Content 숨기기 및 교체](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf command-line options](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
