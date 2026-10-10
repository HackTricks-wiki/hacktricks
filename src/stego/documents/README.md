# 문서 스테가노그래피

{{#include ../../banners/hacktricks-training.md}}

많은 문서 형식은 단일 데이터 스트림이 아니라 구조화된 컨테이너입니다:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (임베디드 파일, 스트림)
- Office OOXML (`.docx/.xlsx/.pptx`는 ZIP 파일)
- 레거시 RTF 및 OLE/Compound File Binary 문서. RTF는 텍스트 기반 형식으로 제어 단어와 그룹을 저장하는 반면, OLE 복합 파일은 파일 시스템과 유사한 저장 개체 및 스트림 계층 구조를 제공합니다. 두 형식 모두 숨겨진 데이터나 임베디드 데이터를 찾으려면 형식별 검사가 필요합니다.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### 기법

PDF 파일에는 객체, 스트림, JavaScript 및 임베디드 파일이 포함될 수 있습니다. 분석할 때 흔히 수행하는 작업은 다음과 같습니다.

- 임베디드 첨부 파일 추출.
- 객체 스트림을 확장하여 객체를 더 쉽게 검사.
- JavaScript, 임베디드 이미지 및 비정상적인 스트림 식별.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### 빠른 검사

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

`--qdf --object-streams=disable` 조합은 더 읽기 쉬운 표현을 만들고 object streams를 제거하므로 수동 검사가 쉬워집니다.<sup>[[2]](#references)</sup> 그런 다음 `out.pdf`에서 의심스러운 객체와 문자열을 검색합니다.

## Office OOXML

### 기법

Office Open XML 파일(`.docx`, `.xlsx`, `.pptx`)은 Open Packaging Conventions를 사용합니다. 이는 ZIP 기반 패키지로, 여러 구성 요소와 XML 관계 파일로 이루어져 있습니다.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> 패키지를 관계 그래프로 보고 미디어, 외부 관계, 특이한 사용자 지정 구성 요소를 검사합니다.

실제로는 다음과 같습니다.

- 문서는 XML과 에셋으로 이루어진 디렉터리 트리입니다.
- `_rels/` 관계 파일은 외부 리소스나 숨겨진 구성 요소를 가리킬 수 있습니다.
- 삽입된 데이터는 대개 `word/media/`, 사용자 지정 XML 구성 요소 또는 특이한 관계에 있습니다.

### 빠른 점검

```bash
7z l file.docx
7z x file.docx -oout
```

그런 다음 다음을 확인합니다.

- `word/document.xml`
- 외부 관계가 있는 `word/_rels/`
- `word/media/`의 포함된 미디어

## References

- [1] [Poppler pdfdetach 매뉴얼](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [qpdf 문서 - QDF 모드 및 객체 스트림](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Open Packaging Conventions 기본 사항](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Office Open XML 파일 형식](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Compound File Binary File Format 소개](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - RTF 사양 참고 자료](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
