# Stego

{{#include ../banners/hacktricks-training.md}}

이 섹션은 파일(이미지/오디오/비디오/문서/아카이브)과 텍스트 기반 steganography에서 숨겨진 데이터를 **발견하고 추출하는 것**에 중점을 둡니다.

암호학 공격을 보러 왔다면 **Crypto** 섹션으로 가세요.

## 진입점

steganography를 포렌식 문제로 접근하세요: 실제 컨테이너를 식별하고, 주요 신호 위치(메타데이터, 추가된 데이터, 포함된 파일)를 열거한 다음에야 콘텐츠 수준의 추출 기법을 적용합니다.

### 워크플로우 및 분류

컨테이너 식별, 메타데이터/문자열 검사, carving, 포맷별 분기 등을 우선시하는 구조화된 워크플로우입니다.
{{#ref}}
workflow/README.md
{{#endref}}

### 이미지

대부분의 CTF stego가 주로 등장하는 분야: LSB/bit-planes (PNG/BMP), chunk/file-format weirdness, JPEG tooling, 및 다중 프레임 GIF 트릭.
{{#ref}}
images/README.md
{{#endref}}

### 오디오

Spectrogram 메시지, 샘플 LSB 임베딩, 및 전화 키패드 톤(DTMF)이 반복되는 패턴입니다.
{{#ref}}
audio/README.md
{{#endref}}

### 텍스트

텍스트가 정상적으로 렌더링되지만 예상치 못하게 동작한다면, Unicode 동형문자, 제로폭 문자, 또는 공백 기반 인코딩을 고려하세요.
{{#ref}}
text/README.md
{{#endref}}

### 문서

PDFs 및 Office 파일은 우선 컨테이너입니다; 공격은 보통 포함된 파일/스트림, 객체/관계 그래프, 그리고 ZIP 추출을 중심으로 전개됩니다.
{{#ref}}
documents/README.md
{{#endref}}

### Malware 및 delivery-style steganography

Payload 전달은 픽셀 수준의 은닉보다, 마커로 구분된 텍스트 payload를 담은 유효해 보이는 파일(예: GIF/PNG)을 자주 사용합니다.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
