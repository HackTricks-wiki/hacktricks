# 문서 Steganography

{{#include ../../banners/hacktricks-training.md}}

문서는 종종 단순한 컨테이너일 뿐입니다:

- PDF (embedded files, streams)
- Office OOXML (`.docx/.xlsx/.pptx`는 ZIP)
- RTF / OLE 레거시 형식

## PDF

### Technique

PDF는 objects, streams 및 선택적 embedded files로 구성된 구조화된 컨테이너입니다. CTF에서는 다음 작업이 필요한 경우가 많습니다:

- embedded attachments 추출
- 콘텐츠를 검색할 수 있도록 object streams 압축 해제/flatten
- hidden objects 식별 (JS, embedded images, 특이한 streams)

### 빠른 점검
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Then search inside `out.pdf` for suspicious objects/strings.

## Office OOXML

### 기법

OOXML을 ZIP + XML relationship graph로 취급하세요. payloads는 종종 media, relationships 또는 특이한 custom parts에 숨겨집니다.

OOXML files are ZIP containers. That means:

- 문서는 XML 및 assets의 directory tree입니다.
- `_rels/` relationship files는 external resources 또는 숨겨진 parts를 가리킬 수 있습니다.
- Embedded data는 `word/media/`, custom XML parts 또는 비정상적인 relationships에 자주 존재합니다.

### 빠른 확인
```bash
7z l file.docx
7z x file.docx -oout
```
그런 다음 다음을 검사합니다:

- `word/document.xml`
- 외부 관계가 있는 `word/_rels/`
- `word/media/`에 포함된 media


{{#include ../../banners/hacktricks-training.md}}
