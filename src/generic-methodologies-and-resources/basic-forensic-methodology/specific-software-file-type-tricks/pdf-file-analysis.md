# PDF 파일 분석

{{#include ../../../banners/hacktricks-training.md}}

**자세한 내용은 다음을 확인하세요:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF 형식은 복잡하고 데이터를 숨길 가능성이 있어 CTF 포렌식 문제의 주요 대상입니다. 일반 텍스트 요소와 바이너리 객체를 결합하며, 객체는 압축되거나 암호화될 수 있고 JavaScript나 Flash 같은 언어로 작성된 스크립트를 포함할 수도 있습니다. PDF 구조를 이해하려면 Didier Stevens의 [입문 자료](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)를 참고하거나 텍스트 편집기 또는 Origami 같은 PDF 전용 편집기를 사용할 수 있습니다.

PDF를 심층적으로 조사하거나 조작할 때는 [qpdf](https://github.com/qpdf/qpdf) 및 [Origami](https://github.com/mobmewireless/origami-pdf) 같은 도구를 사용할 수 있습니다. PDF 내부의 숨겨진 데이터는 다음 위치에 감춰져 있을 수 있습니다.

- 보이지 않는 레이어
- Adobe의 XMP 메타데이터 형식
- 증분 생성 데이터
- 배경과 같은 색상의 텍스트
- 이미지 뒤의 텍스트 또는 겹쳐진 이미지
- 표시되지 않는 주석

PDF를 맞춤형으로 분석하려면 [PeepDF](https://github.com/jesparza/peepdf) 같은 Python 라이브러리를 사용해 전용 파싱 스크립트를 작성할 수 있습니다. 또한 PDF는 숨겨진 데이터를 저장할 가능성이 매우 커서, 원래 위치에서는 더 이상 호스팅되지 않지만 PDF의 위험과 대응책에 관한 NSA 가이드도 여전히 유용한 정보를 제공합니다. 가이드 [사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)과 Ange Albertini가 정리한 [PDF 형식 트릭 모음](https://github.com/corkami/docs/blob/master/PDF/PDF.md)을 통해 이 주제를 더 자세히 살펴볼 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

## 흔히 악용되는 구성 요소

공격자는 문서를 열거나 상호작용할 때 자동으로 실행되는 특정 PDF 객체와 동작을 악용하는 경우가 많습니다. 다음 키워드를 찾아보세요.

* **/OpenAction, /AA** – 문서를 열 때 또는 특정 이벤트에서 실행되는 자동 동작.
* **/JS, /JavaScript** – 내장 JavaScript(종종 난독화되거나 여러 객체에 나뉘어 있음).
* **/Launch, /SubmitForm, /URI, /GoToE** – 외부 프로세스 또는 URL 실행 기능.
* **/RichMedia, /Flash, /3D** – 페이로드를 숨길 수 있는 멀티미디어 객체.
* **/EmbeddedFile /Filespec** – 파일 첨부(EXE, DLL, OLE 등).
* **/ObjStm, /XFA, /AcroForm** – shellcode를 숨기는 데 흔히 악용되는 객체 스트림 또는 양식.
* **증분 업데이트** – 여러 개의 %%EOF 마커가 있거나 **/Prev** 오프셋이 매우 크면 AV를 우회하기 위해 서명 후 데이터가 추가되었음을 나타낼 수 있습니다.

앞서 언급한 토큰이 의심스러운 문자열(powershell, cmd.exe, calc.exe, base64 등)과 함께 나타나면 해당 PDF를 더 깊이 분석해야 합니다.

---

## 정적 분석 치트 시트

아래 예제에서는 문서화된 `pdf-parser.py`, qpdf 및 pdfcpu 명령줄 인터페이스를 사용합니다.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

PDF 안에서 이미지를 픽셀화해도 이미지의 원래 픽셀은 제거되지 않습니다. 읽을 수 있는 문서에서 이런 방식으로 자격 증명을 숨긴 것처럼 보인다면, 권한이 있는 오프라인 분석을 위해 삽입된 이미지를 추출하세요. 결과는 이미지와 적절한 참조 자료에 따라 달라지며, 시각적 복구가 보장되지는 않습니다. 복구한 비밀번호는 권한이 중요한 계정에서 별도로 검증해야 합니다. PDF 추출이나 이미지 복구 작업을 일상적인 호스트 열거 스캔에 포함하지 마세요.

추가로 유용한 프로젝트(2023~2025년 활발히 유지 관리됨):
* **pdfcpu** – PDF를 검증, 복호화, 추출, 최적화 및 조작할 수 있는 Go 라이브러리/CLI입니다.<sup>[[9]](#references)</sup>
* **pdf-inspector** – 객체 그래프와 스트림을 렌더링하는 브라우저 기반 시각화 도구입니다.
* **PyMuPDF** – PDF를 검사하고 페이지를 래스터 이미지로 렌더링할 수 있는 스크립트 가능한 Python 바인딩입니다. 파서/렌더러는 신뢰할 수 없는 파일의 공격 표면으로 간주하고, 적절히 격리된 분석 환경에서 실행하세요.<sup>[[8]](#references)</sup>

---

## 최근 공격 기법 (2023~2025)

* **PDF 다형성 파일 MalDoc (2023)** – JPCERT/CC는 VBA 매크로가 포함된 Word로 만든 MHT 파일을 PDF 뒤에 추가해, PDF magic을 유지하면서 Word에서도 열리게 하는 기법을 보고했습니다. PDF 전용 분석 도구, 샌드박스 또는 백신은 악성 동작이 Word로 열었을 때 발생하므로 매크로를 놓칠 수 있습니다. `<w:WordDocument>` 마커와 다른 MHT 지표가 함께 있는지 확인하세요.<sup>[[2]](#references)</sup>
* **서명된 PDF에 대한 Shadow 공격** – 공격자는 PDF에 서명하기 전에 숨겨진 콘텐츠를 넣은 다음, 카탈로그나 객체 참조를 변경하는 증분 업데이트를 추가해 원래 서명이 유효한 상태로 유지되는 동안 뷰어에 숨겨진 콘텐츠가 표시되게 할 수 있습니다. 이 기법은 이런 업데이트를 무해한 것으로 분류하는 뷰어를 우회할 수 있습니다.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe는 이 치명적인 취약점을 임의 코드 실행으로 이어질 수 있는 use-after-free로 평가했습니다. APSB24-29는 2024년 5월 14일에 게시되었습니다.<sup>[[3]](#references)</sup>

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

1. **빠른 패치 적용** – Acrobat/Reader를 최신 Continuous 트랙으로 유지하세요. 실제 공격에서 관찰된 RCE 체인 대부분은 수개월 전에 패치된 n-day 취약점을 악용합니다.
2. **게이트웨이에서 활성 콘텐츠 제거** – JavaScript, 임베디드 파일, 실행 액션, 폼, 멀티미디어를 명시적으로 제거하는 전용 정책 제어형 sanitizer 또는 CDR 제품을 사용하세요. `qpdf --qdf`를 사용하면 PDF 객체를 더 쉽게 검사할 수 있고, pdfcpu는 유효성 검사 및 조작 기능을 제공합니다. 어느 명령도 단독으로 활성 콘텐츠가 제거되었다는 증거가 되지는 않습니다.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – 시각적 충실도를 유지하면서 활성 객체를 제거하려면 샌드박스 호스트에서 PDF를 이미지(또는 PDF/A)로 변환하세요.
4. **드물게 사용하는 기능 차단** – Reader의 엔터프라이즈 “Enhanced Security” 설정으로 JavaScript, 멀티미디어, 3D 렌더링을 비활성화할 수 있습니다.
5. **사용자 교육** – 소셜 엔지니어링(송장 및 이력서 미끼)은 여전히 초기 침투 경로입니다. 의심스러운 첨부 파일을 IR 담당자에게 전달하도록 직원들을 교육하세요.

## References

- [1] [포렌식 CTF 현장 가이드](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – PDF 파일에 악성 Word 파일을 삽입해 탐지 우회](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe 보안 공지 – Adobe Acrobat 및 Reader 보안 업데이트 제공 (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - 가이드 사본](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF 형식 트릭](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: 서명된 PDF에서 콘텐츠 숨기기 및 대체하기](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF 튜토리얼](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf 명령줄 옵션](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
