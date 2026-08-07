# Stego

{{#include ../banners/hacktricks-training.md}}

이 섹션에서는 파일(이미지/오디오/비디오/문서/아카이브)과 텍스트 기반 steganography에서 **숨겨진 데이터 찾기 및 추출**에 초점을 맞춥니다.

암호학적 공격을 찾고 있다면 **Crypto** 섹션으로 이동하세요.

## 시작점

steganography를 포렌식 문제로 접근하세요. 실제 컨테이너를 식별하고, 신호가 강한 위치(메타데이터, 추가된 데이터, 임베디드 파일)를 열거한 다음, 콘텐츠 수준의 추출 기법을 적용하세요.

### 워크플로 및 triage

컨테이너 식별, 메타데이터/문자열 검사, carving 및 포맷별 분기를 우선시하는 구조화된 워크플로입니다.

{{#ref}}
workflow/README.md
{{#endref}}

### 이미지

대부분의 CTF stego가 이루어지는 영역입니다. LSB/bit-planes (PNG/BMP), chunk/file-format의 특이점, JPEG tooling 및 multi-frame GIF 트릭을 다룹니다.

{{#ref}}
images/README.md
{{#endref}}

### 오디오

Spectrogram 메시지, sample LSB embedding 및 전화 키패드 톤(DTMF)은 반복적으로 등장하는 패턴입니다.

{{#ref}}
audio/README.md
{{#endref}}

### 텍스트

텍스트가 정상적으로 렌더링되지만 예상과 다르게 동작한다면 Unicode homoglyphs, zero-width characters 또는 whitespace-based encoding을 고려하세요.

{{#ref}}
text/README.md
{{#endref}}

### 문서

PDF와 Office 파일은 우선 컨테이너로 보아야 합니다. 공격은 일반적으로 embedded files/streams, object/relationship graphs 및 ZIP extraction을 중심으로 이루어집니다.

{{#ref}}
documents/README.md
{{#endref}}

### Malware 및 delivery-style steganography

Payload delivery는 pixel-level hiding보다는 marker-delimited text payloads를 포함하는, 정상적으로 보이는 파일(예: GIF/PNG)을 자주 사용합니다.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
