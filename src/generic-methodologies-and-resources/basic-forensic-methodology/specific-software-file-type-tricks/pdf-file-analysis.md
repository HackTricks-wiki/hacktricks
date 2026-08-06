# PDF 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

**자세한 내용은 다음을 확인하세요:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF format은 복잡성과 data를 숨길 수 있는 가능성으로 잘 알려져 있어 CTF forensics challenges의 주요 대상이 됩니다. PDF는 일반 텍스트 요소와 binary objects를 결합하며, 이러한 objects는 압축되거나 암호화될 수 있고 JavaScript 또는 Flash와 같은 언어로 작성된 scripts를 포함할 수도 있습니다. PDF structure를 이해하려면 Didier Stevens의 [입문 자료](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)를 참고하거나, text editor 또는 Origami와 같은 PDF 전용 editor를 사용할 수 있습니다.

PDF를 심층적으로 탐색하거나 조작하려면 [qpdf](https://github.com/qpdf/qpdf) 및 [Origami](https://github.com/mobmewireless/origami-pdf)와 같은 tools를 사용할 수 있습니다. PDF 내부의 hidden data는 다음과 같은 위치에 숨겨질 수 있습니다.

- 보이지 않는 layers
- Adobe의 XMP metadata format
- Incremental generations
- 배경과 같은 색상의 text
- images 뒤 또는 겹쳐진 images
- 표시되지 않는 comments

Custom PDF analysis를 위해 [PeepDF](https://github.com/jesparza/peepdf)와 같은 Python libraries를 사용하여 맞춤형 parsing scripts를 작성할 수 있습니다. 또한 PDF는 hidden data를 저장할 수 있는 가능성이 매우 크기 때문에, 더 이상 원래 위치에서 호스팅되지는 않지만 PDF risks 및 countermeasures에 대한 NSA guide와 같은 resources도 여전히 유용한 정보를 제공합니다. [guide 사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)과 Ange Albertini이 작성한 [PDF format tricks 모음](https://github.com/corkami/docs/blob/master/PDF/PDF.md)을 통해 이 주제를 더 살펴볼 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

## 일반적인 악성 constructs

Attackers는 문서를 열거나 상호작용할 때 자동으로 실행되는 특정 PDF objects 및 actions를 자주 악용합니다. 다음 keywords를 찾아볼 가치가 있습니다.

* **/OpenAction, /AA** – 문서가 열리거나 특정 events가 발생할 때 실행되는 automatic actions
* **/JS, /JavaScript** – embedded JavaScript (대개 obfuscated되거나 여러 objects로 분할됨)
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers
* **/RichMedia, /Flash, /3D** – payloads를 숨길 수 있는 multimedia objects
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE 등)
* **/ObjStm, /XFA, /AcroForm** – shell-code를 숨기는 데 흔히 악용되는 object streams 또는 forms
* **Incremental updates** – 여러 개의 %%EOF markers 또는 매우 큰 **/Prev** offset은 AV를 우회하기 위해 signing 이후 data가 appended되었음을 나타낼 수 있습니다.

이전 tokens 중 하나라도 suspicious strings (powershell, cmd.exe, calc.exe, base64 등)와 함께 나타나면 해당 PDF를 더 심층적으로 분석해야 합니다.

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
추가로 유용한 프로젝트(2023-2025년 기준 active maintenance):
* **pdfcpu** – PDF를 *lint*, *decrypt*, *extract*, *compress* 및 *sanitize*할 수 있는 Go library/CLI.
* **pdf-inspector** – object graph와 streams를 렌더링하는 browser-based visualizer.
* **PyMuPDF (fitz)** – hardened sandbox에서 embedded JS를 detonate할 수 있도록 페이지를 안전하게 이미지로 렌더링하는 scriptable Python engine.

---

## 최신 attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC는 threat actors가 MHT-based Word document와 VBA macros를 최종 **%%EOF** 뒤에 추가하여, valid PDF이면서 valid DOC이기도 한 파일을 생성한 사례를 관찰했습니다. PDF layer만 parsing하는 AV engines는 macro를 놓칩니다. Static PDF keywords는 clean 상태이지만, `file`은 여전히 `%PDF`를 출력합니다. 문자열 `<w:WordDocument>`도 포함하는 모든 PDF를 highly suspicious한 것으로 취급해야 합니다.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries는 incremental update feature를 악용하여, benign first revision에 서명이 유지된 상태에서 malicious `/OpenAction`이 포함된 두 번째 **/Catalog**을 삽입합니다. 첫 번째 xref table만 검사하는 tools는 우회됩니다.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – 취약한 **CoolType.dll** function은 embedded CIDType2 fonts에서 도달할 수 있으며, crafted document를 열면 user의 privileges로 remote code execution이 가능합니다. 2024년 5월 APSB24-29에서 patch되었습니다.<sup>[[3]](#references)</sup>

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

1. **빠르게 패치하기** – Acrobat/Reader를 최신 Continuous track으로 유지하세요. 실제 환경에서 관찰된 대부분의 RCE 체인은 수개월 전에 수정된 n-day 취약점을 악용합니다.
2. **게이트웨이에서 active content 제거하기** – `pdfcpu sanitize` 또는 `qpdf --qdf --remove-unreferenced`를 사용해 수신 PDF에서 JavaScript, embedded files 및 launch actions를 제거하세요.
3. **Content Disarm & Reconstruction (CDR)** – sandbox host에서 PDF를 이미지(또는 PDF/A)로 변환해 시각적 충실도는 유지하면서 active objects를 제거하세요.
4. **거의 사용되지 않는 기능 차단하기** – Reader의 enterprise “Enhanced Security” 설정을 사용하면 JavaScript, multimedia 및 3D rendering을 비활성화할 수 있습니다.
5. **사용자 교육** – social engineering(송장 및 이력서 lure)은 여전히 초기 vector입니다. 의심스러운 첨부 파일을 IR로 전달하도록 직원에게 교육하세요.

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – PDF 파일에 악성 Word 파일을 삽입하는 Detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat 및 Reader용 Security update 제공 (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - guide 사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
