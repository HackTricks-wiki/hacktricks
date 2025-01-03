# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}

자세한 정보는 [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)를 확인하세요. 이것은 요약입니다:

Microsoft는 많은 오피스 문서 형식을 만들었으며, 두 가지 주요 유형은 **OLE 형식**(RTF, DOC, XLS, PPT 등)과 **Office Open XML (OOXML) 형식**(DOCX, XLSX, PPTX 등)입니다. 이러한 형식은 매크로를 포함할 수 있어 피싱 및 악성 소프트웨어의 표적이 됩니다. OOXML 파일은 zip 컨테이너로 구조화되어 있어 압축 해제를 통해 파일 및 폴더 계층과 XML 파일 내용을 확인할 수 있습니다.

OOXML 파일 구조를 탐색하기 위해 문서를 압축 해제하는 명령과 출력 구조가 제공됩니다. 이러한 파일에 데이터를 숨기는 기술이 문서화되어 있으며, CTF 도전 과제 내에서 데이터 은닉에 대한 지속적인 혁신을 나타냅니다.

분석을 위해 **oletools**와 **OfficeDissector**는 OLE 및 OOXML 문서를 검사하기 위한 포괄적인 도구 세트를 제공합니다. 이러한 도구는 종종 악성 소프트웨어 배포의 벡터 역할을 하는 임베디드 매크로를 식별하고 분석하는 데 도움을 줍니다. VBA 매크로 분석은 Libre Office를 활용하여 Microsoft Office 없이 수행할 수 있으며, 이는 중단점 및 감시 변수를 사용한 디버깅을 허용합니다.

**oletools**의 설치 및 사용은 간단하며, pip를 통해 설치하고 문서에서 매크로를 추출하는 명령이 제공됩니다. 매크로의 자동 실행은 `AutoOpen`, `AutoExec` 또는 `Document_Open`과 같은 함수에 의해 트리거됩니다.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
