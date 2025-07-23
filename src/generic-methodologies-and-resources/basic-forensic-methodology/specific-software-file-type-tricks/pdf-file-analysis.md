# PDF 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

**자세한 내용은 확인하세요:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF 형식은 복잡성과 데이터를 숨길 수 있는 잠재력으로 잘 알려져 있어 CTF 포렌식 챌린지의 중심이 됩니다. 이는 일반 텍스트 요소와 이진 객체를 결합하며, 이진 객체는 압축되거나 암호화될 수 있고, JavaScript나 Flash와 같은 언어로 작성된 스크립트를 포함할 수 있습니다. PDF 구조를 이해하기 위해 Didier Stevens의 [소개 자료](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)를 참조하거나 텍스트 편집기 또는 Origami와 같은 PDF 전용 편집기를 사용할 수 있습니다.

PDF를 심층적으로 탐색하거나 조작하기 위해 [qpdf](https://github.com/qpdf/qpdf) 및 [Origami](https://github.com/mobmewireless/origami-pdf)와 같은 도구를 사용할 수 있습니다. PDF 내 숨겨진 데이터는 다음과 같은 곳에 숨겨져 있을 수 있습니다:

- 보이지 않는 레이어
- Adobe의 XMP 메타데이터 형식
- 점진적 생성
- 배경과 같은 색상의 텍스트
- 이미지 뒤의 텍스트 또는 겹치는 이미지
- 표시되지 않는 주석

맞춤형 PDF 분석을 위해 [PeepDF](https://github.com/jesparza/peepdf)와 같은 Python 라이브러리를 사용하여 맞춤형 파싱 스크립트를 작성할 수 있습니다. 또한 PDF의 숨겨진 데이터 저장 가능성은 매우 방대하여, 원래 위치에서 더 이상 호스팅되지 않지만 PDF 위험 및 대응 조치에 대한 NSA 가이드와 같은 자료는 여전히 귀중한 통찰을 제공합니다. [가이드의 사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%Bútmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)과 Ange Albertini의 [PDF 형식 트릭 모음](https://github.com/corkami/docs/blob/master/PDF/PDF.md)은 이 주제에 대한 추가 읽기를 제공할 수 있습니다.

## 일반적인 악성 구성 요소

공격자는 문서가 열리거나 상호작용할 때 자동으로 실행되는 특정 PDF 객체와 작업을 자주 악용합니다. 검색할 가치가 있는 키워드는 다음과 같습니다:

* **/OpenAction, /AA** – 열거나 특정 이벤트에서 실행되는 자동 작업.
* **/JS, /JavaScript** – 포함된 JavaScript(종종 난독화되거나 객체에 분할됨).
* **/Launch, /SubmitForm, /URI, /GoToE** – 외부 프로세스 / URL 실행기.
* **/RichMedia, /Flash, /3D** – 페이로드를 숨길 수 있는 멀티미디어 객체.
* **/EmbeddedFile /Filespec** – 파일 첨부(EXE, DLL, OLE 등).
* **/ObjStm, /XFA, /AcroForm** – 쉘 코드를 숨기기 위해 일반적으로 악용되는 객체 스트림 또는 양식.
* **점진적 업데이트** – 여러 %%EOF 마커 또는 매우 큰 **/Prev** 오프셋은 서명 후 데이터가 추가되었음을 나타낼 수 있습니다.

이전의 토큰이 의심스러운 문자열(예: powershell, cmd.exe, calc.exe, base64 등)과 함께 나타나면 PDF는 더 깊은 분석이 필요합니다.

---

## 정적 분석 요약표
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
추가로 유용한 프로젝트 (2023-2025년 동안 활발히 유지됨):
* **pdfcpu** – PDF를 *lint*, *decrypt*, *extract*, *compress* 및 *sanitize*할 수 있는 Go 라이브러리/CLI.
* **pdf-inspector** – 객체 그래프와 스트림을 렌더링하는 브라우저 기반 시각화 도구.
* **PyMuPDF (fitz)** – 안전하게 페이지를 이미지로 렌더링하여 강화된 샌드박스에서 내장된 JS를 실행할 수 있는 스크립트 가능한 Python 엔진.

---

## 최근 공격 기술 (2023-2025)

* **PDF 폴리글롯의 MalDoc (2023)** – JPCERT/CC는 위협 행위자가 최종 **%%EOF** 이후에 VBA 매크로가 포함된 MHT 기반 Word 문서를 추가하는 것을 관찰하였으며, 이는 유효한 PDF이자 유효한 DOC인 파일을 생성합니다. PDF 레이어만 파싱하는 AV 엔진은 매크로를 놓칩니다. 정적 PDF 키워드는 깨끗하지만 `file`은 여전히 `%PDF`를 출력합니다. `<w:WordDocument>` 문자열이 포함된 PDF는 매우 의심스럽게 취급해야 합니다.
* **Shadow-incremental 업데이트 (2024)** – 적들은 악성 `/OpenAction`이 있는 두 번째 **/Catalog**를 삽입하기 위해 증분 업데이트 기능을 악용하며, 무해한 첫 번째 수정본은 서명된 상태로 유지합니다. 첫 번째 xref 테이블만 검사하는 도구는 우회됩니다.
* **폰트 파싱 UAF 체인 – CVE-2024-30284 (Acrobat/Reader)** – 취약한 **CoolType.dll** 함수는 내장된 CIDType2 폰트에서 접근할 수 있으며, 조작된 문서가 열리면 사용자의 권한으로 원격 코드 실행이 가능합니다. 2024년 5월 APSB24-29에서 패치됨.

---

## YARA 빠른 규칙 템플릿
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

1. **빠른 패치** – Acrobat/Reader를 최신 Continuous 트랙으로 유지하십시오; 실제에서 관찰된 대부분의 RCE 체인은 몇 달 전에 수정된 n-day 취약점을 활용합니다.
2. **게이트웨이에서 활성 콘텐츠 제거** – `pdfcpu sanitize` 또는 `qpdf --qdf --remove-unreferenced`를 사용하여 수신 PDF에서 JavaScript, 포함된 파일 및 실행 작업을 제거하십시오.
3. **콘텐츠 무장 해제 및 재구성 (CDR)** – 샌드박스 호스트에서 PDF를 이미지(또는 PDF/A)로 변환하여 활성 객체를 버리면서 시각적 충실도를 유지하십시오.
4. **드물게 사용되는 기능 차단** – Reader의 기업 “향상된 보안” 설정을 통해 JavaScript, 멀티미디어 및 3D 렌더링을 비활성화할 수 있습니다.
5. **사용자 교육** – 사회 공학(청구서 및 이력서 유인물)은 초기 벡터로 남아 있습니다; 직원들에게 의심스러운 첨부 파일을 IR에 전달하도록 교육하십시오.

## 참고 문헌

* JPCERT/CC – “PDF의 MalDoc – 악성 Word 파일을 PDF 파일에 포함시켜 탐지 우회” (2023년 8월)
* Adobe – Acrobat 및 Reader에 대한 보안 업데이트 (APSB24-29, 2024년 5월)


{{#include ../../../banners/hacktricks-training.md}}
