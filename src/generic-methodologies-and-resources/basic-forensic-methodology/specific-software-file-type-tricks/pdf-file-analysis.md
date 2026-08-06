# PDF 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

**자세한 내용은 다음을 확인하세요:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF 형식은 복잡하고 데이터를 숨길 가능성이 있는 것으로 알려져 있어 CTF forensics challenge의 주요 대상입니다. PDF는 일반 텍스트 요소와 binary object를 결합하며, 이러한 object는 압축되거나 암호화될 수 있고 JavaScript나 Flash 같은 언어의 script를 포함할 수도 있습니다. PDF 구조를 이해하려면 Didier Stevens의 [입문 자료](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)를 참고하거나 text editor 또는 Origami 같은 PDF 전용 editor를 사용할 수 있습니다.

PDF를 심층적으로 분석하거나 조작하려면 [qpdf](https://github.com/qpdf/qpdf) 및 [Origami](https://github.com/mobmewireless/origami-pdf) 같은 도구를 사용할 수 있습니다. PDF 내부의 hidden data는 다음과 같은 위치에 숨겨질 수 있습니다.

- 보이지 않는 layer
- Adobe의 XMP metadata format
- Incremental generation
- 배경과 같은 색상의 text
- image 뒤에 있거나 서로 겹쳐 있는 text
- 표시되지 않는 comment

사용자 지정 PDF 분석에는 [PeepDF](https://github.com/jesparza/peepdf) 같은 Python library를 사용해 맞춤형 parsing script를 작성할 수 있습니다. 또한 PDF의 hidden data 저장 가능성은 매우 방대하므로, 원래 위치에서는 더 이상 호스팅되지 않는 NSA의 PDF risks and countermeasures guide도 여전히 유용한 정보를 제공합니다. [guide 사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)과 Ange Albertini이 작성한 [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) 모음에서도 이 주제에 대해 더 살펴볼 수 있습니다.

## 일반적인 악성 구성 요소

공격자는 문서를 열거나 상호작용할 때 자동으로 실행되는 특정 PDF object와 action을 자주 악용합니다. 다음 keyword를 탐색할 가치가 있습니다.

* **/OpenAction, /AA** – 문서를 열 때 또는 특정 event에서 실행되는 automatic action.
* **/JS, /JavaScript** – embedded JavaScript(종종 여러 object에 걸쳐 난독화되거나 분할됨).
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launcher.
* **/RichMedia, /Flash, /3D** – payload를 숨길 수 있는 multimedia object.
* **/EmbeddedFile /Filespec** – file attachment(EXE, DLL, OLE 등).
* **/ObjStm, /XFA, /AcroForm** – shell-code를 숨기는 데 자주 악용되는 object stream 또는 form.
* **Incremental updates** – 여러 개의 %%EOF marker 또는 매우 큰 **/Prev** offset은 AV를 우회하기 위해 signing 이후에 data가 추가되었음을 나타낼 수 있습니다.

앞의 token 중 하나라도 suspicious string(powershell, cmd.exe, calc.exe, base64 등)과 함께 나타나면 해당 PDF를 더 깊이 분석해야 합니다.

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
추가로 유용한 프로젝트(2023-2025년 현재 활발히 유지 관리됨):
* **pdfcpu** – PDF를 *lint*, *decrypt*, *extract*, *compress* 및 *sanitize*할 수 있는 Go library/CLI.
* **pdf-inspector** – object graph와 streams를 렌더링하는 browser-based visualizer.
* **PyMuPDF (fitz)** – 강화된 sandbox에서 embedded JS를 안전하게 실행하기 위해 pages를 images로 렌더링할 수 있는 scriptable Python engine.

---

## 최근 attack techniques (2023-2025년)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC는 threat actors가 VBA macros가 포함된 MHT-based Word document를 최종 **%%EOF** 뒤에 추가하여, 하나의 파일이 valid PDF이면서 valid DOC가 되도록 만든 사례를 관찰했다. PDF layer만 parsing하는 AV engines는 macro를 놓친다. Static PDF keywords는 clean하지만, `file`은 여전히 `%PDF`를 출력한다. 문자열 `<w:WordDocument>`도 포함하는 모든 PDF를 highly suspicious한 것으로 간주해야 한다.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries는 incremental update feature를 악용하여, benign first revision은 signed 상태로 유지하면서 malicious `/OpenAction`이 포함된 두 번째 **/Catalog**을 삽입한다. 첫 번째 xref table만 검사하는 tools는 우회된다.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – embedded CIDType2 fonts를 통해 취약한 **CoolType.dll** function에 도달할 수 있으며, crafted document가 열리면 user의 privileges로 remote code execution이 가능하다. APSB24-29에서 2024년 5월에 patch되었다.<sup>[[3]](#references)</sup>

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

1. **빠르게 패치** – Acrobat/Reader를 최신 Continuous track으로 유지하세요. 실제 공격에서 관찰된 대부분의 RCE chain은 수개월 전에 수정된 n-day vulnerabilities를 악용합니다.
2. **gateway에서 active content 제거** – `pdfcpu sanitize` 또는 `qpdf --qdf --remove-unreferenced`를 사용해 유입되는 PDF에서 JavaScript, embedded files 및 launch actions를 제거하세요.
3. **Content Disarm & Reconstruction (CDR)** – sandbox host에서 PDF를 이미지(또는 PDF/A)로 변환하여 시각적 충실도는 유지하면서 active objects를 제거하세요.
4. **거의 사용되지 않는 기능 차단** – Reader의 enterprise “Enhanced Security” 설정을 사용하면 JavaScript, multimedia 및 3D rendering을 비활성화할 수 있습니다.
5. **사용자 교육** – social engineering(invoice 및 resume lure)은 여전히 initial vector입니다. 의심스러운 attachments를 IR 팀에 전달하도록 직원에게 교육하세요.

## 참고 자료

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – PDF 파일에 악성 Word 파일을 삽입하여 Detection bypass](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Adobe Acrobat 및 Reader에 대한 Security update available (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
