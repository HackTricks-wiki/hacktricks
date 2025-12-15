# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

문서는 종종 단순한 컨테이너입니다:

- PDF (내장된 파일, 스트림)
- Office OOXML (`.docx/.xlsx/.pptx` are ZIPs)
- RTF / OLE 구형 형식

## PDF

### Technique

PDF는 오브젝트, 스트림, 선택적 내장 파일을 포함하는 구조화된 컨테이너입니다. CTFs에서는 종종 다음을 수행해야 합니다:

- 내장된 첨부파일 추출
- 오브젝트 스트림의 압축 해제/평탄화로 콘텐츠를 검색할 수 있게 하기
- 숨겨진 오브젝트(JS, 내장 이미지, 이상한 스트림) 식별

### 빠른 점검
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
그런 다음 `out.pdf` 내부에서 의심스러운 객체/문자열을 검색하세요.

## Office OOXML

### 기법

OOXML을 ZIP + XML 관계 그래프로 간주하세요; payloads는 종종 media, relationships 또는 이상한 custom parts에 숨겨져 있습니다.

OOXML 파일은 ZIP 컨테이너입니다. 즉:

- 문서는 XML과 assets의 디렉터리 트리입니다.
- `_rels/` relationship files는 외부 리소스나 숨겨진 파트를 가리킬 수 있습니다.
- 내장 데이터는 흔히 `word/media/`, custom XML parts 또는 비정상적인 relationships에 존재합니다.

### 빠른 점검
```bash
7z l file.docx
7z x file.docx -oout
```
다음 항목을 검사하세요:

- `word/document.xml`
- `word/_rels/`에서 외부 관계를 확인하세요
- 임베디드 미디어: `word/media/`

{{#include ../../banners/hacktricks-training.md}}
