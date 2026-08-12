# Stego

{{#include ../banners/hacktricks-training.md}}

이 섹션에서는 이미지, 오디오, 비디오, 문서, 아카이브 및 텍스트에서 **숨겨진 데이터를 찾고 추출하는 방법**을 다룹니다. Steganography는 데이터를 다른 데이터 내부에 삽입하여 통신의 존재를 숨깁니다.<sup>[[1]](#references)</sup>

암호화 공격을 찾고 있다면 **Crypto** 섹션으로 이동하세요.

## 진입점

Steganography를 포렌식 문제로 접근하세요. 실제 컨테이너를 식별하고, 신호가 강한 위치(메타데이터, 추가된 데이터, 임베디드 파일)를 조사한 후에 콘텐츠 수준의 추출 기법을 적용해야 합니다.

### Workflow 및 triage

컨테이너 식별, 메타데이터/문자열 검사, carving 및 형식별 분기 처리를 우선하는 구조화된 Workflow입니다.

{{#ref}}
workflow/README.md
{{#endref}}

### 이미지

대부분의 CTF stego가 발생하는 영역입니다. LSB/bit-planes(PNG/BMP), chunk/file-format의 특이점, JPEG tooling 및 multi-frame GIF 트릭을 다룹니다.

{{#ref}}
images/README.md
{{#endref}}

### 오디오

Spectrogram 메시지, sample LSB embedding 및 전화 키패드 톤(DTMF)은 반복적으로 등장하는 패턴입니다.

{{#ref}}
audio/README.md
{{#endref}}

### 텍스트

텍스트가 정상적으로 렌더링되지만 예상과 다르게 동작한다면 Unicode homoglyphs, zero-width characters 또는 whitespace 기반 인코딩을 고려하세요.

{{#ref}}
text/README.md
{{#endref}}

### 문서

PDF와 Office 파일은 우선 컨테이너로 봐야 합니다. 공격은 일반적으로 임베디드 파일/스트림, object/relationship 그래프 및 ZIP 추출을 중심으로 이루어집니다.

{{#ref}}
documents/README.md
{{#endref}}

### Malware 및 delivery 스타일 steganography

Payload delivery에는 GIF 또는 PNG 이미지처럼 정상적으로 보이지만, 픽셀에 데이터를 숨기는 대신 marker로 구분된 텍스트 payload를 포함하는 유효한 파일을 사용할 수 있습니다.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Glossary - Steganography](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
