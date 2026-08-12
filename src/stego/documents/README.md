# 문서 Steganography

{{#include ../../banners/hacktricks-training.md}}

많은 문서 형식은 단일 데이터 스트림이 아니라 구조화된 컨테이너입니다:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (embedded files, streams)
- Office OOXML (`.docx/.xlsx/.pptx`는 ZIP)
- Legacy RTF 및 OLE/Compound File Binary 문서. RTF는 텍스트 중심 형식으로 control words와 groups를 저장하는 반면, OLE compound files는 storage objects와 streams로 이루어진 파일 시스템과 유사한 계층 구조를 노출합니다. 따라서 두 형식 모두 숨겨진 데이터나 embedded data를 찾기 위해 형식별 검사가 필요합니다.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Technique

PDF 파일에는 objects, streams, JavaScript 및 embedded files가 포함될 수 있습니다. 분석 중 일반적인 작업은 다음과 같습니다:

- embedded attachments 추출.
- objects를 더 쉽게 검사할 수 있도록 object streams 확장.
- JavaScript, embedded images 및 비정상적인 streams 식별.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### 빠른 점검
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
`--qdf --object-streams=disable` 조합은 더 읽기 쉬운 표현을 생성하고 object streams를 제거하므로 수동 검사가 더 쉬워집니다.<sup>[[2]](#references)</sup> 그런 다음 `out.pdf`에서 의심스러운 객체와 문자열을 검색합니다.

## Office OOXML

### 기법

Office Open XML 파일(`.docx`, `.xlsx`, `.pptx`)은 ZIP 기반 패키지로 구성된 Open Packaging Conventions를 사용하며, 이 패키지는 parts와 XML 관계 파일로 이루어집니다.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> 패키지를 관계 그래프로 간주하고 미디어, 외부 관계, 특이한 사용자 지정 parts를 검사합니다.

실제로:

- 문서는 XML과 asset으로 구성된 디렉터리 트리입니다.
- `_rels/` 관계 파일은 외부 리소스나 숨겨진 parts를 가리킬 수 있습니다.
- Embedded data는 `word/media/`, 사용자 지정 XML parts 또는 특이한 관계에 존재하는 경우가 많습니다.

### 빠른 확인
```bash
7z l file.docx
7z x file.docx -oout
```
그런 다음 다음을 검사합니다:

- `word/document.xml`
- 외부 relationships가 있는 `word/_rels/`
- `word/media/`의 embedded media

## References

- [1] [Poppler pdfdetach 매뉴얼](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf 문서 - QDF mode 및 object streams](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions fundamentals](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML file formats](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary File Format introduction](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF specification reference](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
